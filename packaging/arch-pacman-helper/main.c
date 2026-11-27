#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <alpm.h>
#include <alpm_list.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SYSTEM_DATABASE "/var/lib/pacman/"
#define GLOBAL_HOOKS "/usr/share/libalpm/hooks/"
#define LOCAL_HOOKS "/etc/pacman.d/hooks/"
#define SYSTEM_LOG "/var/log/pacman.log"
#define MAX_CONFIG_BYTES (128 * 1024)
#define MAX_FIELD_BYTES 250
#define MAX_HOOKS 4096
#define MAX_CTIME_NANOS 999999999

struct record_identity {
    uint64_t device;
    uint64_t inode;
    uint64_t ctime_seconds;
    uint64_t ctime_nanoseconds;
};

struct request {
    const char *name;
    const char *version;
    uint64_t installed;
    struct record_identity descriptor;
};

static int failure(const char *message)
{
    fprintf(stderr, "uninstallany-pacman-helper: %s\n", message);
    return EXIT_FAILURE;
}

static int alpm_failure(alpm_handle_t *handle, const char *message)
{
    fprintf(stderr, "uninstallany-pacman-helper: %s (%s)\n", message,
            alpm_strerror(alpm_errno(handle)));
    return EXIT_FAILURE;
}

static void report_alpm_log(void *context, alpm_loglevel_t level, const char *format, va_list args)
{
    bool *reported_error = context;
    if ((level & ALPM_LOG_ERROR) != 0)
        *reported_error = true;
    if ((level & (ALPM_LOG_ERROR | ALPM_LOG_WARNING)) != 0)
        vfprintf(stderr, format, args);
}

static bool decimal(const char *text, uint64_t *result)
{
    uint64_t value = 0;
    if (*text == '\0' || (text[0] == '0' && text[1] != '\0'))
        return false;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9')
            return false;
        const uint64_t digit = (uint64_t)(*cursor - '0');
        if (value > (UINT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    *result = value;
    return true;
}

static bool valid_field(const char *text, const char *punctuation)
{
    if (!isalnum((unsigned char)*text) || strlen(text) > MAX_FIELD_BYTES)
        return false;
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (!isalnum((unsigned char)*cursor) && strchr(punctuation, *cursor) == NULL)
            return false;
    }
    return true;
}

static bool authorize_process(void)
{
    const char *caller = getenv("PKEXEC_UID");
    uint64_t uid;
    // The package installs an ordinary executable. pkexec supplies root
    // privileges only after system authorization.
    if (getuid() != 0 || geteuid() != 0 || caller == NULL || !decimal(caller, &uid) || uid == 0 ||
        uid >= UINT32_MAX)
        return false;
    return clearenv() == 0 && chdir("/") == 0 &&
           setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1) == 0 && setenv("HOME", "/", 1) == 0 &&
           setenv("LC_ALL", "C", 1) == 0;
}

static bool trusted_stat(const struct stat *entry, mode_t type)
{
    return (entry->st_mode & S_IFMT) == type && entry->st_uid == 0 && (entry->st_mode & 0022) == 0;
}

// Callers pass fixed absolute paths. Never follow an ancestor symlink.
static int trusted_directory(const char *path)
{
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    int fd = open("/", flags);
    if (fd < 0)
        return -1;
    struct stat entry;
    if (fstat(fd, &entry) != 0 || !trusted_stat(&entry, S_IFDIR)) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    char *copy = strdup(path + 1);
    if (copy == NULL) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }
    char *state = NULL;
    for (char *name = strtok_r(copy, "/", &state); name != NULL;
         name = strtok_r(NULL, "/", &state)) {
        const int next = openat(fd, name, flags);
        const int saved = errno;
        close(fd);
        fd = next;
        if (fd < 0) {
            free(copy);
            errno = saved;
            return -1;
        }
        if (fstat(fd, &entry) != 0 || !trusted_stat(&entry, S_IFDIR)) {
            close(fd);
            free(copy);
            errno = EPERM;
            return -1;
        }
    }
    free(copy);
    return fd;
}

static int trusted_file(int directory, const char *name)
{
    struct stat named;
    if (fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) != 0)
        return -1;
    if (!trusted_stat(&named, S_IFREG)) {
        errno = EPERM;
        return -1;
    }
    const int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat held;
    if (fstat(fd, &held) != 0 || !trusted_stat(&held, S_IFREG) || named.st_dev != held.st_dev ||
        named.st_ino != held.st_ino) {
        close(fd);
        errno = EPERM;
        return -1;
    }
    return fd;
}

// Use the opened record because the package install time only has second
// precision and can match a replacement of the same version.
static bool matches_desc(int directory, const struct record_identity *expected)
{
    const int desc = trusted_file(directory, "desc");
    if (desc < 0)
        return false;
    struct stat entry;
    const bool matches = fstat(desc, &entry) == 0 && entry.st_ctim.tv_sec > 0 &&
                         (uint64_t)entry.st_dev == expected->device &&
                         (uint64_t)entry.st_ino == expected->inode &&
                         (uint64_t)entry.st_ctim.tv_sec == expected->ctime_seconds &&
                         (uint64_t)entry.st_ctim.tv_nsec == expected->ctime_nanoseconds;
    close(desc);
    return matches;
}

static bool trusted_record(int database, const char *record, const struct record_identity *expected)
{
    const int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    const int dir = openat(database, record, flags);
    if (dir < 0)
        return false;
    struct stat entry;
    bool trusted =
        fstat(dir, &entry) == 0 && trusted_stat(&entry, S_IFDIR) && matches_desc(dir, expected) &&
        fstatat(dir, "files", &entry, AT_SYMLINK_NOFOLLOW) == 0 && trusted_stat(&entry, S_IFREG);
    if (trusted) {
        const int install = fstatat(dir, "install", &entry, AT_SYMLINK_NOFOLLOW);
        trusted = install == 0 ? trusted_stat(&entry, S_IFREG) : errno == ENOENT;
    }
    close(dir);
    return trusted;
}

static bool trusted_log(void)
{
    const int log = trusted_directory("/var/log");
    if (log < 0)
        return false;
    struct stat entry;
    const int result = fstatat(log, "pacman.log", &entry, AT_SYMLINK_NOFOLLOW);
    const bool trusted = result == 0 ? trusted_stat(&entry, S_IFREG) : errno == ENOENT;
    close(log);
    return trusted;
}

static bool path_equals(const char *actual, const char *expected)
{
    size_t left = strlen(actual);
    size_t right = strlen(expected);
    while (left > 1 && actual[left - 1] == '/')
        --left;
    while (right > 1 && expected[right - 1] == '/')
        --right;
    return left == right && memcmp(actual, expected, left) == 0;
}

static bool verify_hooks(const char *path, bool optional)
{
    const int fd = trusted_directory(path);
    if (fd < 0)
        return optional && errno == ENOENT;
    DIR *directory = fdopendir(fd);
    if (directory == NULL) {
        close(fd);
        return false;
    }
    bool verified = false;
    size_t count = 0;
    for (;;) {
        errno = 0;
        const struct dirent *entry = readdir(directory);
        if (entry == NULL) {
            verified = errno == 0;
            break;
        }
        const char *name = entry->d_name;
        const size_t length = strlen(name);
        if (length < 5 || strcmp(name + length - 5, ".hook") != 0)
            continue;
        struct stat attributes;
        if (++count > MAX_HOOKS || fstatat(fd, name, &attributes, AT_SYMLINK_NOFOLLOW) != 0)
            break;
        // Native pacman allows /dev/null to mask a system hook. A link
        // elsewhere would require independent proof of its target.
        if (S_ISLNK(attributes.st_mode) && attributes.st_uid == 0) {
            char target[sizeof("/dev/null")];
            const ssize_t size = readlinkat(fd, name, target, sizeof(target));
            if (size == (ssize_t)(sizeof("/dev/null") - 1) &&
                memcmp(target, "/dev/null", sizeof("/dev/null") - 1) == 0)
                continue;
        }
        if (!trusted_stat(&attributes, S_IFREG))
            break;
    }
    closedir(directory);
    return verified;
}

static bool configure_hooks(alpm_handle_t *handle)
{
    const alpm_list_t *hooks = alpm_option_get_hookdirs(handle);
    return hooks != NULL && hooks->next == NULL && path_equals(hooks->data, GLOBAL_HOOKS) &&
           verify_hooks(GLOBAL_HOOKS, false) && verify_hooks(LOCAL_HOOKS, true) &&
           alpm_option_add_hookdir(handle, LOCAL_HOOKS) == 0;
}

static char *trim(char *text)
{
    while (isspace((unsigned char)*text))
        ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1]))
        --end;
    *end = '\0';
    return text;
}

static bool load_config(int directory, const char *name, char *buffer)
{
    int fd = trusted_file(directory, name);
    if (fd < 0)
        return false;
    FILE *stream = fdopen(fd, "r");
    if (stream == NULL) {
        close(fd);
        return false;
    }
    const size_t length = fread(buffer, 1, MAX_CONFIG_BYTES + 1, stream);
    const bool complete = !ferror(stream) && feof(stream);
    fclose(stream);
    if (!complete || length > MAX_CONFIG_BYTES || memchr(buffer, '\0', length) != NULL)
        return false;
    buffer[length] = '\0';
    return true;
}

static bool same_directive(const char *key, const char *const *allowed, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(key, allowed[i]) == 0)
            return true;
    }
    return false;
}

static bool protected_pattern(const char *pattern, alpm_pkg_t *package, bool group)
{
    if (*pattern == '!' || *pattern == '\\')
        return true;
    if (!group)
        return fnmatch(pattern, alpm_pkg_get_name(package), 0) == 0;
    for (const alpm_list_t *item = alpm_pkg_get_groups(package); item != NULL; item = item->next) {
        if (fnmatch(pattern, item->data, 0) == 0)
            return true;
    }
    return false;
}

static bool global_option(alpm_handle_t *handle, alpm_pkg_t *package, const char *key, char *value)
{
    const char *const flags[] = {"Color",
                                 "NoProgressBar",
                                 "VerbosePkgLists",
                                 "ILoveCandy",
                                 "DisableSandbox",
                                 "DisableSandboxFilesystem",
                                 "DisableSandboxSyscalls",
                                 "DisableDownloadTimeout"};
    const char *const download_only[] = {"Architecture",      "GPGDir",
                                         "CacheDir",          "SigLevel",
                                         "LocalFileSigLevel", "RemoteFileSigLevel",
                                         "CleanMethod",       "ParallelDownloads",
                                         "DownloadUser"};
    if (strcmp(key, "CheckSpace") == 0)
        return value == NULL && alpm_option_set_checkspace(handle, 1) == 0;
    if (strcmp(key, "UseSyslog") == 0)
        return value == NULL && alpm_option_set_usesyslog(handle, 1) == 0;
    if (same_directive(key, flags, sizeof(flags) / sizeof(flags[0])))
        return value == NULL;
    if (value == NULL || *value == '\0')
        return false;
    if (same_directive(key, download_only, sizeof(download_only) / sizeof(download_only[0])))
        return true;
    if (strcmp(key, "RootDir") == 0)
        return path_equals(value, "/");
    if (strcmp(key, "DBPath") == 0)
        return path_equals(value, SYSTEM_DATABASE);
    if (strcmp(key, "LogFile") == 0)
        return strcmp(value, SYSTEM_LOG) == 0;
    if (strcmp(key, "HookDir") == 0)
        return path_equals(value, LOCAL_HOOKS);

    const bool protect_group = strcmp(key, "IgnoreGroup") == 0;
    const bool protect_package = strcmp(key, "HoldPkg") == 0 || strcmp(key, "IgnorePkg") == 0;
    const bool no_upgrade = strcmp(key, "NoUpgrade") == 0;
    const bool no_extract = strcmp(key, "NoExtract") == 0;
    if (!(protect_group || protect_package || no_upgrade || no_extract))
        return false;
    if (strchr(value, '#') != NULL || strchr(value, '\t') != NULL)
        return false;
    char *state = NULL;
    for (char *token = strtok_r(value, " ", &state); token != NULL;
         token = strtok_r(NULL, " ", &state)) {
        if ((protect_group || protect_package) && protected_pattern(token, package, protect_group))
            return false;
        // NoUpgrade also participates in libalpm removal disposition.
        if (no_upgrade && alpm_option_add_noupgrade(handle, token) != 0)
            return false;
        if (no_extract && alpm_option_add_noextract(handle, token) != 0)
            return false;
    }
    return true;
}

static bool mirrorlist_is_repo_only(void)
{
    const int directory = trusted_directory("/etc/pacman.d");
    if (directory < 0)
        return false;
    char buffer[MAX_CONFIG_BYTES + 1];
    const bool loaded = load_config(directory, "mirrorlist", buffer);
    close(directory);
    if (!loaded)
        return false;
    char *state = NULL;
    for (char *line = strtok_r(buffer, "\n", &state); line != NULL;
         line = strtok_r(NULL, "\n", &state)) {
        line = trim(line);
        if (*line == '\0' || *line == '#')
            continue;
        char *equal = strchr(line, '=');
        if (equal == NULL)
            return false;
        *equal = '\0';
        const char *key = trim(line);
        if (strcmp(key, "Server") != 0 && strcmp(key, "CacheServer") != 0)
            return false;
    }
    return true;
}

static bool apply_config(alpm_handle_t *handle, alpm_pkg_t *package)
{
    const int directory = trusted_directory("/etc");
    if (directory < 0)
        return false;
    char buffer[MAX_CONFIG_BYTES + 1];
    const bool loaded = load_config(directory, "pacman.conf", buffer);
    close(directory);
    if (!loaded)
        return false;

    const char *const repository[] = {"Server", "CacheServer", "SigLevel", "Usage"};
    bool seen_section = false;
    bool seen_options = false;
    bool options = false;
    bool checked_mirrorlist = false;
    char *state = NULL;
    for (char *line = strtok_r(buffer, "\n", &state); line != NULL;
         line = strtok_r(NULL, "\n", &state)) {
        line = trim(line);
        if (*line == '\0' || *line == '#')
            continue;
        if (line[0] == '[') {
            const size_t length = strlen(line);
            if (length <= 2 || line[length - 1] != ']')
                return false;
            line[length - 1] = '\0';
            const char *section = line + 1;
            if (!valid_field(section, "._+-"))
                return false;
            options = strcmp(section, "options") == 0;
            if (options && seen_options)
                return false;
            seen_options |= options;
            seen_section = true;
            continue;
        }
        if (!seen_section)
            return false;
        char *value = strchr(line, '=');
        if (value != NULL) {
            *value++ = '\0';
            value = trim(value);
        }
        const char *key = trim(line);
        if (options) {
            if (!global_option(handle, package, key, value))
                return false;
        } else if (strcmp(key, "Include") == 0) {
            // An included file can contain [options]. Accept only the
            // stock mirrorlist after proving it defines no global options.
            if (value == NULL || strcmp(value, "/etc/pacman.d/mirrorlist") != 0 ||
                (!checked_mirrorlist && !mirrorlist_is_repo_only()))
                return false;
            checked_mirrorlist = true;
        } else if (value == NULL || *value == '\0' ||
                   !same_directive(key, repository, sizeof(repository) / sizeof(repository[0]))) {
            return false;
        }
    }
    return seen_options;
}

static bool protected_package(alpm_pkg_t *package)
{
    const char *const exact[] = {
        "amd-ucode",   "archlinux-keyring",
        "base",        "base-devel",
        "bash",        "coreutils",
        "dracut",      "filesystem",
        "glibc",       "grub",
        "intel-ucode", "libalpm",
        "mkinitcpio",  "pacman",
        "polkit",      "sudo",
        "systemd",     "uninstallany-pacman-helper",
        "util-linux",
    };
    const char *name = alpm_pkg_get_name(package);
    if (name == NULL || same_directive(name, exact, sizeof(exact) / sizeof(exact[0])) ||
        strcmp(name, "linux") == 0 || strncmp(name, "linux-", 6) == 0 ||
        strncmp(name, "pacman-", 7) == 0 || strncmp(name, "systemd-", 8) == 0)
        return true;
    // Keep bootable kernels even when a custom package uses another name.
    const alpm_filelist_t *files = alpm_pkg_get_files(package);
    if (files == NULL)
        return true;
    for (size_t i = 0; i < files->count; ++i) {
        const char *path = files->files[i].name;
        if (path == NULL)
            return true;
        const size_t length = strlen(path);
        if (strncmp(path, "boot/vmlinuz", 12) == 0 ||
            (length >= sizeof("usr/lib/modules//vmlinuz") - 1 &&
             strncmp(path, "usr/lib/modules/", 16) == 0 &&
             strcmp(path + length - 8, "/vmlinuz") == 0))
            return true;
    }
    return false;
}

static bool matches_request(alpm_pkg_t *package, const struct request *request)
{
    if (package == NULL)
        return false;
    const char *name = alpm_pkg_get_name(package);
    const char *version = alpm_pkg_get_version(package);
    const alpm_time_t date = alpm_pkg_get_installdate(package);
    return name != NULL && version != NULL && strcmp(name, request->name) == 0 &&
           strcmp(version, request->version) == 0 && date > 0 &&
           (uint64_t)date == request->installed &&
           alpm_pkg_get_reason(package) == ALPM_PKG_REASON_EXPLICIT;
}

static void free_missing_dependency(void *entry) { alpm_depmissing_free(entry); }

static int remove_locked(alpm_handle_t *handle, int database, const struct request *request,
                         const bool *reported_error)
{
    // Verify the anchored database record before libalpm can read its
    // metadata or load its installation scriptlet.
    char record[NAME_MAX + 1];
    const int length = snprintf(record, sizeof(record), "%s-%s", request->name, request->version);
    if (length < 0 || (size_t)length >= sizeof(record) ||
        !trusted_record(database, record, &request->descriptor))
        return failure("the reviewed local package record changed or is unsafe");
    alpm_db_t *local = alpm_get_localdb(handle);
    if (local == NULL || alpm_db_get_valid(local) != 0)
        return alpm_failure(handle, "the local package database could not be verified");
    alpm_pkg_t *package = alpm_db_get_pkg(local, request->name);
    if (!matches_request(package, request))
        return failure("the reviewed package changed or was installed as a dependency");
    if (protected_package(package) || !apply_config(handle, package))
        return failure("the package is protected or pacman configuration could not be verified");
    if (!configure_hooks(handle) || !trusted_log() ||
        alpm_option_set_logfile(handle, SYSTEM_LOG) != 0)
        return failure("system pacman hooks or logging could not be verified");
    if (alpm_remove_pkg(handle, package) != 0)
        return alpm_failure(handle, "could not queue the reviewed package");

    alpm_list_t *details = NULL;
    if (alpm_trans_prepare(handle, &details) != 0) {
        const alpm_errno_t error = alpm_errno(handle);
        if (error == ALPM_ERR_UNSATISFIED_DEPS)
            alpm_list_free_inner(details, free_missing_dependency);
        alpm_list_free(details);
        return alpm_failure(handle, "pacman dependency or transaction preflight failed");
    }
    alpm_list_free(details);
    const alpm_list_t *remove = alpm_trans_get_remove(handle);
    // libalpm can diagnose duplicate or corrupt entries while populating its
    // cache, then continue with a partial view of installed packages.
    if (*reported_error || remove == NULL || remove->next != NULL ||
        alpm_trans_get_add(handle) != NULL || !matches_request(remove->data, request))
        return failure("the prepared transaction is not one exact package removal");

    details = NULL;
    const int result = alpm_trans_commit(handle, &details);
    alpm_list_free(details);
    if (result != 0 || *reported_error)
        return alpm_failure(handle, "pacman commit failed; package state may have changed");

    // libalpm updates its in-memory cache during removal. Also verify that
    // the exact package directory is gone from the on-disk local database.
    struct stat entry;
    if (alpm_db_get_pkg(local, request->name) != NULL ||
        alpm_errno(handle) != ALPM_ERR_PKG_NOT_FOUND ||
        fstatat(database, record, &entry, AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
        return failure("pacman returned success but package absence could not be verified");
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (!authorize_process())
        return failure("invoke through administrator authorization");
    struct request request;
    struct record_identity *descriptor = &request.descriptor;
    if (argc != 9 || strcmp(argv[1], "remove") != 0 || !valid_field(argv[2], "@._+-") ||
        !valid_field(argv[3], ":@._+-~^") || !decimal(argv[4], &request.installed) ||
        request.installed == 0 || request.installed > INT64_MAX ||
        !decimal(argv[5], &descriptor->device) || !decimal(argv[6], &descriptor->inode) ||
        !decimal(argv[7], &descriptor->ctime_seconds) || descriptor->ctime_seconds == 0 ||
        descriptor->ctime_seconds > INT64_MAX ||
        !decimal(argv[8], &descriptor->ctime_nanoseconds) ||
        descriptor->ctime_nanoseconds > MAX_CTIME_NANOS)
        return failure("expected remove NAME VERSION INSTALLDATE DEV INO CTIME_SEC CTIME_NSEC");
    request.name = argv[2];
    request.version = argv[3];

    const int database = trusted_directory(SYSTEM_DATABASE "local");
    if (database < 0)
        return failure("the trusted local pacman database directory is unavailable");
    const int database_version = trusted_file(database, "ALPM_DB_VERSION");
    if (database_version < 0) {
        close(database);
        return failure("the trusted pacman database version file is unavailable");
    }
    close(database_version);
    alpm_errno_t error;
    alpm_handle_t *handle = alpm_initialize("/", SYSTEM_DATABASE, &error);
    if (handle == NULL) {
        close(database);
        return failure(alpm_strerror(error));
    }

    // Zero flags preserve dependencies, backups, hooks and scriptlets and
    // leave libalpm in charge of acquiring and releasing db.lck.
    int result;
    bool reported_error = false;
    if (alpm_option_set_logcb(handle, report_alpm_log, &reported_error) != 0) {
        result = alpm_failure(handle, "could not attach pacman diagnostics");
    } else if (alpm_trans_init(handle, 0) != 0) {
        result = alpm_failure(handle, "could not lock the local pacman database");
    } else {
        result = remove_locked(handle, database, &request, &reported_error);
        if (alpm_trans_release(handle) != 0 && result == EXIT_SUCCESS)
            result = alpm_failure(handle, "could not release the pacman transaction");
    }
    alpm_release(handle);
    close(database);
    return result;
}
