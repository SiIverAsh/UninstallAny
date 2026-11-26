#import "installer_ownership.h"

#include <dispatch/dispatch.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum {
    MaximumPackageBatch = 48,
    MaximumArgumentCount = 2 + 2 * MaximumPackageBatch,
    MaximumOutputBytes = 64 * 1024 * 1024,
    ReadBufferBytes = 16 * 1024,
    ExitPollMilliseconds = 20,
    ReapPollMilliseconds = 100,
    MaximumQuerySeconds = 12,
};

static const char InstallerProgram[] = "/usr/sbin/pkgutil";

typedef struct {
    int reader;
    int writer;
} UAQueryPipe;

static void UACloseQueryFD(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static void UACloseQueryPipe(UAQueryPipe *pipe) {
    UACloseQueryFD(&pipe->reader);
    UACloseQueryFD(&pipe->writer);
}

static int UAOpenQueryPipe(UAQueryPipe *queryPipe) {
    int descriptors[2];
    if (pipe(descriptors) != 0) {
        return errno;
    }
    // Keep the pipe descriptors distinct from the child's three standard fds.
    queryPipe->reader = fcntl(descriptors[0], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
    int error = queryPipe->reader < 0 ? errno : 0;
    if (error == 0) {
        queryPipe->writer = fcntl(descriptors[1], F_DUPFD_CLOEXEC, STDERR_FILENO + 1);
        error = queryPipe->writer < 0 ? errno : 0;
    }
    close(descriptors[0]);
    close(descriptors[1]);
    if (error == 0 && fcntl(queryPipe->reader, F_SETFL, O_NONBLOCK) != 0) {
        error = errno;
    }
    return error;
}

static bool UAASCIILetterOrDigit(unsigned char character) {
    return (character >= '0' && character <= '9')
        || (character >= 'A' && character <= 'Z')
        || (character >= 'a' && character <= 'z');
}

static bool UAInstallerIDIsSafe(const char *identifier) {
    size_t length = strlen(identifier);
    if (length == 0 || length > NAME_MAX || !UAASCIILetterOrDigit(identifier[0])) {
        return false;
    }
    bool previousDot = false;
    for (size_t index = 1; index < length; index++) {
        unsigned char character = identifier[index];
        if (character == '.') {
            if (previousDot || index == length - 1) {
                return false;
            }
            previousDot = true;
        } else if (UAASCIILetterOrDigit(character) || character == '-' || character == '_') {
            previousDot = false;
        } else {
            return false;
        }
    }
    return true;
}

static bool UAInstallerAnchorIsSafe(NSString *path) {
    static NSString *const Prefix = @"/Applications/";
    if (![path hasPrefix:Prefix] || [path containsString:@"\\"]
        || [path rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location != NSNotFound) {
        return false;
    }
    NSArray<NSString *> *parts = [[path substringFromIndex:Prefix.length]
        componentsSeparatedByString:@"/"];
    NSString *basename = parts.firstObject;
    if (basename.length <= 4 || [basename hasPrefix:@"."]
        || [basename.pathExtension caseInsensitiveCompare:@"app"] != NSOrderedSame) {
        return false;
    }
    if (parts.count == 1) {
        return true;
    }
    if (![parts[1] isEqualToString:@"Contents"]) {
        return false;
    }
    if (parts.count == 3) {
        return [parts[2] isEqualToString:@"Info.plist"];
    }
    NSString *leaf = parts.lastObject;
    return parts.count == 4 && [parts[2] isEqualToString:@"MacOS"] && leaf.length > 0
        && ![leaf isEqualToString:@"."] && ![leaf isEqualToString:@".."];
}

static bool UAInstallerArguments(NSArray<NSString *> *arguments,
                                NSMutableArray<NSData *> *argumentStorage, char **argv) {
    NSUInteger count = arguments.count;
    if (count < 3 || count > MaximumArgumentCount || ![arguments[0] isEqual:@"--volume"]
        || ![arguments[1] isEqual:@"/"]) {
        return false;
    }
    argv[0] = (char *)InstallerProgram;
    for (NSUInteger index = 0; index < count; index++) {
        NSString *argument = arguments[index];
        if (![argument isKindOfClass:NSString.class]) {
            return false;
        }
        size_t length = [argument lengthOfBytesUsingEncoding:NSUTF8StringEncoding];
        if (length == 0 || length >= PATH_MAX) {
            return false;
        }
        NSMutableData *buffer = [NSMutableData dataWithLength:length + 1];
        if (![argument getCString:buffer.mutableBytes maxLength:buffer.length
                          encoding:NSUTF8StringEncoding] || strlen(buffer.bytes) != length) {
            return false;
        }
        [argumentStorage addObject:buffer];
        argv[index + 1] = buffer.mutableBytes;
    }
    argv[count + 1] = NULL;

    NSString *operation = arguments[2];
    if ([operation isEqualToString:@"--pkgs-plist"]) {
        return count == 3;
    }
    if ([operation isEqualToString:@"--file-info-plist"]) {
        return count == 4 && UAInstallerAnchorIsSafe(arguments[3]);
    }
    bool listMetadata = [operation isEqualToString:@"--pkg-info"];
    bool listFiles = [operation isEqualToString:@"--files"];
    if ((!listMetadata && !listFiles) || count < 4 || count % 2 != 0) {
        return false;
    }
    for (NSUInteger index = 2; index < count; index += 2) {
        if (![arguments[index] isEqualToString:operation] || !UAInstallerIDIsSafe(argv[index + 2])) {
            return false;
        }
    }
    return true;
}

static void UADestroyQueryActions(posix_spawn_file_actions_t *actions) {
    if (*actions != NULL) {
        posix_spawn_file_actions_destroy(actions);
    }
}

static void UADestroyQueryAttributes(posix_spawnattr_t *attributes) {
    if (*attributes != NULL) {
        posix_spawnattr_destroy(attributes);
    }
}

static int UASetQueryWorkingDirectory(posix_spawn_file_actions_t *actions) {
#if __MAC_OS_X_VERSION_MAX_ALLOWED >= 260000
    if (@available(macOS 26.0, *)) {
        return posix_spawn_file_actions_addchdir(actions, "/");
    }
#endif
    // The _np spelling is the supported API on the minimum macOS version.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    return posix_spawn_file_actions_addchdir_np(actions, "/");
#pragma clang diagnostic pop
}

static int UASpawnInstallerQuery(char *const *argv, int stdoutWriter, int stderrWriter,
                                 pid_t *child) {
    posix_spawn_file_actions_t actions __attribute__((cleanup(UADestroyQueryActions))) = NULL;
    posix_spawnattr_t attributes __attribute__((cleanup(UADestroyQueryAttributes))) = NULL;
    int error = posix_spawn_file_actions_init(&actions);
    if (error == 0) {
        error = posix_spawnattr_init(&attributes);
    }
    if (error == 0) {
        error = UASetQueryWorkingDirectory(&actions);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_adddup2(&actions, stdoutWriter, STDOUT_FILENO);
    }
    if (error == 0) {
        error = posix_spawn_file_actions_adddup2(&actions, stderrWriter, STDERR_FILENO);
    }

    sigset_t blocked, defaults;
    sigemptyset(&blocked);
    sigemptyset(&defaults);
    sigaddset(&defaults, SIGPIPE);
    if (error == 0) {
        error = posix_spawnattr_setsigmask(&attributes, &blocked);
    }
    if (error == 0) {
        error = posix_spawnattr_setsigdefault(&attributes, &defaults);
    }
    if (error == 0) {
        error = posix_spawnattr_setpgroup(&attributes, 0);
    }
    if (error == 0) {
        error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_CLOEXEC_DEFAULT
            | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);
    }
    if (error != 0) {
        return error;
    }

    // Package IDs and paths are arguments, and the executable is never searched.
    char *const environment[] = {"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin", NULL};
    return posix_spawn(child, InstallerProgram, &actions, &attributes, argv, environment);
}

static int UAReadQueryOutput(struct pollfd *output, NSMutableData *bytes, size_t maximumOutput) {
    if ((output->revents & POLLNVAL) != 0) {
        return EBADF;
    }
    if ((output->revents & (POLLIN | POLLHUP | POLLERR)) == 0) {
        return 0;
    }
    unsigned char buffer[ReadBufferBytes];
    // A single byte of diagnostics makes receipt ownership uncertain.
    const bool diagnostics = bytes == nil;
    ssize_t count = read(output->fd, buffer, diagnostics ? 1 : sizeof(buffer));
    if (count < 0) {
        return errno == EAGAIN || errno == EINTR ? 0 : errno;
    }
    if (count == 0) {
        output->fd = -1;
        return 0;
    }
    if (diagnostics) {
        return EPROTO;
    }
    if ((size_t)count > maximumOutput - bytes.length) {
        return EFBIG;
    }
    [bytes appendBytes:buffer length:(size_t)count];
    return 0;
}

static int UACollectInstallerQuery(pid_t *child, int stdoutReader, int stderrReader,
                                   size_t maximumOutput, uint64_t deadline, NSData **output) {
    struct pollfd pipes[] = {{stderrReader, POLLIN, 0}, {stdoutReader, POLLIN, 0}};
    NSMutableData *bytes = [NSMutableData data];
    for (;;) {
        uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
        if (now >= deadline) {
            return ETIMEDOUT;
        }
        bool pipesClosed = pipes[0].fd < 0 && pipes[1].fd < 0;
        if (pipesClosed) {
            // Retain the child's process ID until both pipes drain. A process
            // that inherited a writer must not hold the request open forever.
            int waitStatus;
            pid_t waited = waitpid(*child, &waitStatus, WNOHANG);
            if (waited > 0) {
                *child = -1;
                if (!WIFEXITED(waitStatus) || WEXITSTATUS(waitStatus) != 0) {
                    return EPROTO;
                }
                if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
                    return ETIMEDOUT;
                }
                *output = bytes;
                return 0;
            }
            if (waited < 0) {
                if (errno == EINTR) {
                    continue;
                }
                if (errno == ECHILD) {
                    *child = -1;
                }
                return errno;
            }
        }

        uint64_t remaining = deadline - now;
        int pollMilliseconds = (int)((remaining + NSEC_PER_MSEC - 1) / NSEC_PER_MSEC);
        if (pipesClosed && pollMilliseconds > ExitPollMilliseconds) {
            pollMilliseconds = ExitPollMilliseconds;
        }
        int ready = poll(pipes, sizeof(pipes) / sizeof(pipes[0]), pollMilliseconds);
        if (ready < 0 && errno != EINTR) {
            return errno;
        }
        if (ready <= 0) {
            continue;
        }
        int error = UAReadQueryOutput(&pipes[0], nil, 0);
        if (error == 0) {
            error = UAReadQueryOutput(&pipes[1], bytes, maximumOutput);
        }
        if (error != 0) {
            return error;
        }
    }
}

static dispatch_semaphore_t UAInstallerQueryGate(void) {
    static dispatch_once_t once;
    static dispatch_semaphore_t gate;
    dispatch_once(&once, ^{
        gate = dispatch_semaphore_create(1);
    });
    return gate;
}

static void UAReapInstallerQuery(pid_t child, dispatch_semaphore_t gate) {
    pid_t waited = waitpid(child, NULL, WNOHANG);
    if (waited == 0 || (waited < 0 && errno == EINTR)) {
        // In-flight reaping holds the gate, so an uninterruptible child
        // cannot consume more process slots or block an XPC request thread.
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, ReapPollMilliseconds * NSEC_PER_MSEC),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                UAReapInstallerQuery(child, gate);
            });
        return;
    }
    dispatch_semaphore_signal(gate);
}

int UARunInstallerQuery(NSArray<NSString *> *arguments, size_t maximumOutput,
                        uint64_t monotonicDeadline, NSData **output) {
    *output = nil;
    NSMutableArray<NSData *> *argumentStorage __attribute__((objc_precise_lifetime)) =
        [NSMutableArray array];
    char *argv[MaximumArgumentCount + 2];
    if (maximumOutput == 0 || maximumOutput > MaximumOutputBytes
        || !UAInstallerArguments(arguments, argumentStorage, argv)) {
        return EINVAL;
    }
    uint64_t now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    uint64_t localDeadline = now + MaximumQuerySeconds * NSEC_PER_SEC;
    uint64_t deadline = monotonicDeadline < localDeadline ? monotonicDeadline : localDeadline;
    if (now >= deadline) {
        return ETIMEDOUT;
    }

    UAQueryPipe stdoutPipe __attribute__((cleanup(UACloseQueryPipe))) = {-1, -1};
    UAQueryPipe stderrPipe __attribute__((cleanup(UACloseQueryPipe))) = {-1, -1};
    int error = UAOpenQueryPipe(&stdoutPipe);
    if (error == 0) {
        error = UAOpenQueryPipe(&stderrPipe);
    }
    if (error != 0) {
        return error;
    }
    dispatch_semaphore_t gate = UAInstallerQueryGate();
    if (dispatch_semaphore_wait(gate, DISPATCH_TIME_NOW) != 0) {
        return EBUSY;
    }

    pid_t child = -1;
    @try {
        if (clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) >= deadline) {
            return ETIMEDOUT;
        }
        pid_t spawned;
        error = UASpawnInstallerQuery(argv, stdoutPipe.writer, stderrPipe.writer, &spawned);
        if (error == 0) {
            child = spawned;
            UACloseQueryFD(&stdoutPipe.writer);
            UACloseQueryFD(&stderrPipe.writer);
            error = UACollectInstallerQuery(&child, stdoutPipe.reader, stderrPipe.reader,
                                            maximumOutput, deadline, output);
        }
    } @finally {
        if (child > 0) {
            // The freshly spawned, unreaped child owns this process group.
            // Kill its group if a descendant still holds a pipe writer.
            if (kill(-child, SIGKILL) != 0 && errno == ESRCH) {
                kill(child, SIGKILL);
            }
            UAReapInstallerQuery(child, gate);
        } else {
            dispatch_semaphore_signal(gate);
        }
    }
    return error;
}
