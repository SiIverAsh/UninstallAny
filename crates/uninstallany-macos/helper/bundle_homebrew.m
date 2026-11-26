#import "bundle_exclusion.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static const int DirectoryFlags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;

static void UACloseDescriptor(int *descriptor) {
    if (*descriptor >= 0) {
        close(*descriptor);
    }
}

static int UARequirePlainACL(int descriptor) {
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        return errno == ENOENT ? 0 : (errno != 0 ? errno : EIO);
    }
    acl_entry_t entry;
    errno = 0;
    int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
    int failure = errno;
    acl_free(acl);
    return result == -1 && (failure == EINVAL || failure == ENOENT) ? 0 : EPERM;
}

static int UAReadProtectedDirectory(int descriptor, struct stat *entry) {
    if (fstat(descriptor, entry) != 0) {
        return errno;
    }
    if (!S_ISDIR(entry->st_mode) || entry->st_uid != 0
        || (entry->st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return EPERM;
    }
    struct statfs volume;
    if (fstatfs(descriptor, &volume) != 0) {
        return errno;
    }
    if (strcmp(volume.f_fstypename, "apfs") != 0 || (volume.f_flags & MNT_LOCAL) == 0
        || (volume.f_flags & MNT_IGNORE_OWNERSHIP) != 0) {
        return ENOTSUP;
    }
    return UARequirePlainACL(descriptor);
}

static int UAOpenProtectedChild(int parent, const char *name, int *child, struct stat *entry) {
    struct stat named;
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno;
    }
    if (!S_ISDIR(named.st_mode)) {
        return S_ISLNK(named.st_mode) ? ELOOP : ENOTDIR;
    }
    int opened __attribute__((cleanup(UACloseDescriptor))) = openat(parent, name, DirectoryFlags);
    if (opened < 0) {
        return errno == ENOENT ? ESTALE : errno;
    }
    int error = UAReadProtectedDirectory(opened, entry);
    if (error != 0) {
        return error == ENOENT ? ESTALE : error;
    }
    if (entry->st_dev != named.st_dev || entry->st_ino != named.st_ino
        || entry->st_birthtimespec.tv_sec != named.st_birthtimespec.tv_sec
        || entry->st_birthtimespec.tv_nsec != named.st_birthtimespec.tv_nsec) {
        return ESTALE;
    }
    *child = opened;
    opened = -1;
    return 0;
}

static int UAReadStartupDataDevice(int root, dev_t systemDevice, dev_t *dataDevice) {
    int system __attribute__((cleanup(UACloseDescriptor))) = -1;
    int volumes __attribute__((cleanup(UACloseDescriptor))) = -1;
    int data __attribute__((cleanup(UACloseDescriptor))) = -1;
    struct stat entry;
    int error = UAOpenProtectedChild(root, "System", &system, &entry);
    if (error == 0 && entry.st_dev == systemDevice) {
        error = UAOpenProtectedChild(system, "Volumes", &volumes, &entry);
    }
    if (error != 0 || entry.st_dev != systemDevice) {
        return error != 0 ? error : EXDEV;
    }
    error = UAOpenProtectedChild(volumes, "Data", &data, &entry);
    if (error == 0) {
        *dataDevice = entry.st_dev;
    }
    return error;
}

static int UARequireEmptyCaskroom(int *descriptor) {
    DIR *entries = fdopendir(*descriptor);
    if (entries == NULL) {
        return errno;
    }
    *descriptor = -1;
    int error = EIO;
    // A directory can contain the two synthetic dot entries. The first
    // other entry is enough to leave its package ownership unresolved.
    for (unsigned int count = 0; count < 3; count++) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (entry == NULL) {
            error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            error = EBUSY;
            break;
        }
    }
    if (closedir(entries) != 0 && error == 0) {
        return errno;
    }
    return error;
}

static int UACheckCaskroom(int root, const char *parentName, const char *prefixName,
                           dev_t systemDevice, dev_t dataDevice) {
    int parent __attribute__((cleanup(UACloseDescriptor))) = -1;
    int prefix __attribute__((cleanup(UACloseDescriptor))) = -1;
    int caskroom __attribute__((cleanup(UACloseDescriptor))) = -1;
    struct stat entry;
    int error = UAOpenProtectedChild(root, parentName, &parent, &entry);
    if (error != 0 || (entry.st_dev != systemDevice && entry.st_dev != dataDevice)) {
        return error == ENOENT ? 0 : (error != 0 ? error : EXDEV);
    }
    error = UAOpenProtectedChild(parent, prefixName, &prefix, &entry);
    if (error != 0 || entry.st_dev != dataDevice) {
        return error == ENOENT ? 0 : (error != 0 ? error : EXDEV);
    }
    error = UAOpenProtectedChild(prefix, "Caskroom", &caskroom, &entry);
    if (error != 0 || entry.st_dev != dataDevice) {
        return error == ENOENT ? 0 : (error != 0 ? error : EXDEV);
    }
    return UARequireEmptyCaskroom(&caskroom);
}

int UACheckStandardCaskrooms(void) {
    int root __attribute__((cleanup(UACloseDescriptor))) = open("/", DirectoryFlags);
    if (root < 0) {
        return errno;
    }
    struct stat entry;
    int error = UAReadProtectedDirectory(root, &entry);
    if (error != 0) {
        return error;
    }
    dev_t dataDevice;
    error = UAReadStartupDataDevice(root, entry.st_dev, &dataDevice);
    if (error != 0) {
        return error;
    }
    error = UACheckCaskroom(root, "opt", "homebrew", entry.st_dev, dataDevice);
    if (error != 0) {
        return error;
    }
    return UACheckCaskroom(root, "usr", "local", entry.st_dev, dataDevice);
}
