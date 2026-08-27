#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>      /* errno for system-call failures */
#include <fcntl.h>      /* open(), O_* flags */
#include <signal.h>     /* raise(), SIGTERM */
#include <stdio.h>      /* printf(), fprintf(), perror(), snprintf() */
#include <stdlib.h>     /* exit(), _Exit(), EXIT_SUCCESS, EXIT_FAILURE, atexit() */
#include <string.h>     /* strerror(), memset() */
#include <sys/resource.h> /* wait4(), struct rusage */
#include <limits.h>     /* PATH_MAX for absolute daemon log path */
#include <sys/stat.h>   /* mkdir(), mode bits */
#include <sys/types.h>  /* pid_t, uid_t, gid_t */
#include <sys/wait.h>   /* wait(), waitpid(), waitid(), W* macros */
#include <unistd.h>     /* fork(), execve(), getpid(), getppid(), getuid(), setsid(), chdir(), close(), dup2(), write() */

/*
    Small Linux process-management demonstrations.

    The examples cover:
      - process identity: PID, PPID, UID/GID, PGID, SID
      - fork() and inherited descriptors
      - execve() replacing the process image
      - exit(), _exit(), atexit(), and SIGCHLD-driven reaping
      - wait(), waitpid(), waitid(), wait4()
      - system()
      - setpgid(), getpgid(), setsid()
      - a contained daemonization pattern

    Some concepts are discussed but not exercised directly:
      - PID 0 (idle) and PID 1 (init/systemd) are kernel/system boot facts
      - vfork() is intentionally omitted because its shared-address-space rules are easy to misuse
      - setuid()/seteuid() transitions need the right privileges or a setuid binary to be meaningful
*/

static void report_wait_status(const char *label, int status)
{
    if (WIFEXITED(status))
    {
        printf("%s: child exited normally with status %d\n",
               label, WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status))
    {
        printf("%s: child died from signal %d%s\n",
               label,
               WTERMSIG(status),
               WCOREDUMP(status) ? " (core dumped)" : "");
    }
    else if (WIFSTOPPED(status))
    {
        printf("%s: child stopped by signal %d\n", label, WSTOPSIG(status));
    }
    else if (WIFCONTINUED(status))
    {
        printf("%s: child continued\n", label);
    }
}


static int ensure_data_dir(void)
{
    if (mkdir("data", 0755) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "main: mkdir(\"data\") failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static void print_identity(const char *label)
{
    pid_t pid = getpid();
    pid_t ppid = getppid();
    pid_t pgid = getpgid(0);
    pid_t sid = getsid(0);

    printf("%s: pid=%ld ppid=%ld pgid=%ld sid=%ld uid=%ld euid=%ld gid=%ld egid=%ld\n",
           label,
           (long)pid,
           (long)ppid,
           (long)pgid,
           (long)sid,
           (long)getuid(),
           (long)geteuid(),
           (long)getgid(),
           (long)getegid());
}

/*
    Demo 1: the process identity visible from user space.

    PIDs and PPIDs identify ancestry.
    PGIDs and SIDs identify job-control structure.
    UIDs and GIDs are the active security credentials.
*/
static void demo_process_identity(void)
{
    printf("\n------ 1. Process identity: getpid(), getppid(), credentials, groups ------\n");
    print_identity("identity");
    printf("identity: PID ceiling is at /proc/sys/kernel/pid_max\n");
    printf("identity: PID 0 is the idle task; PID 1 is the first user-space process\n");
}

/*
    Demo 2: fork() duplicates the calling process.

    The child gets a new PID and its PPID is the parent's PID.
    Both processes continue from the same point in the code independently.
*/
static void demo_fork_and_inheritance(void)
{
    printf("\n------ 2. fork(): duplicated execution and diverging state ------\n");

    pid_t child = fork();
    if (child == -1)
    {
        fprintf(stderr, "fork: fork failed: %s\n", strerror(errno));
        return;
    }

    if (child == 0)
    {
        printf("fork(child):  pid=%ld  ppid=%ld\n", (long)getpid(), (long)getppid());
        _exit(0);
    }

    int status = 0;
    printf("fork(parent): pid=%ld  child=%ld\n", (long)getpid(), (long)child);

    if (waitpid(child, &status, 0) == -1)
    {
        fprintf(stderr, "fork(parent): waitpid failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("fork(parent)", status);
}

/*
    Demo 3: execve() replaces the current program image.

    The child PID stays the same across execve(), but its code, stack, and mappings are replaced.
*/
static void demo_execve(void)
{
    printf("\n------ 3. execve(): replace the child image with a new program ------\n");

    pid_t child = fork();
    if (child == -1)
    {
        fprintf(stderr, "execve: fork failed: %s\n", strerror(errno));
        return;
    }

    if (child == 0)
    {
        char *const argv[] = {"printenv", "DEMO_EXEC", NULL};
        char *const envp[] = {"DEMO_EXEC=execve replaced the child image", NULL};

        printf("execve(child): about to replace pid=%ld with /usr/bin/printenv\n", (long)getpid());
        execve("/usr/bin/printenv", argv, envp);

        fprintf(stderr, "execve(child): execve failed: %s\n", strerror(errno));
        _exit(127);
    }

    int status = 0;
    if (waitpid(child, &status, 0) == -1)
    {
        fprintf(stderr, "execve(parent): waitpid failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("execve(parent)", status);
    printf("execve(parent): the child's PID stayed %ld, but its program image was replaced\n", (long)child);
}

static void atexit_child_handler(void)
{
    printf("exit(child): atexit handler ran before process teardown\n");
}

/*
    Demo 4: exit() performs user-space cleanup, while _exit() does not.
*/
static void demo_exit_variants(void)
{
    printf("\n------ 4. Termination: exit(), _exit(), atexit() ------\n");

    pid_t child_exit = fork();
    if (child_exit == -1)
    {
        fprintf(stderr, "termination: fork for exit() demo failed: %s\n", strerror(errno));
        return;
    }

    if (child_exit == 0)
    {
        if (atexit(atexit_child_handler) != 0)
        {
            fprintf(stderr, "exit(child): atexit registration failed\n");
            _exit(1);
        }
        printf("exit(child): calling exit(10)\n");
        exit(10);
    }

    int status = 0;
    if (waitpid(child_exit, &status, 0) == -1)
    {
        fprintf(stderr, "termination: waitpid for exit() child failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("exit(parent)", status);

    pid_t child__exit = fork();
    if (child__exit == -1)
    {
        fprintf(stderr, "_exit(parent): fork failed: %s\n", strerror(errno));
        return;
    }

    if (child__exit == 0)
    {
        if (atexit(atexit_child_handler) != 0)
        {
            fprintf(stderr, "_exit(child): atexit registration failed\n");
            _exit(1);
        }
        printf("_exit(child): calling _exit(100); atexit handler will not run\n");
        _exit(100);
    }

    if (waitpid(child__exit, &status, 0) == -1)
    {
        fprintf(stderr, "_exit(parent): waitpid failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("_exit(parent)", status);
}

/*
    Demo 5: reaping and status collection.

    wait() reaps any child.
    waitpid() can poll or target a specific child.
    waitid() exposes siginfo_t details.
    wait4() adds resource-usage accounting.
*/
static void demo_wait_interfaces(void)
{
    printf("\n------ 5. Reaping: wait(), waitpid(), waitid(), wait4() ------\n");

    pid_t child_wait = fork();
    if (child_wait == -1)
    {
        fprintf(stderr, "wait: fork child_wait failed: %s\n", strerror(errno));
        return;
    }
    if (child_wait == 0)
        _exit(10);

    int status = 0;
    pid_t reaped = wait(&status);
    if (reaped == -1)
    {
        fprintf(stderr, "wait: wait failed: %s\n", strerror(errno));
        return;
    }
    printf("wait: wait() reaped pid %ld\n", (long)reaped);
    report_wait_status("wait(wait)", status);

    pid_t child_poll = fork();
    if (child_poll == -1)
    {
        fprintf(stderr, "wait: fork child_poll failed: %s\n", strerror(errno));
        return;
    }
    if (child_poll == 0)
    {
        sleep(1);
        _exit(10);
    }

    pid_t poll_result = waitpid(child_poll, &status, WNOHANG);
    if (poll_result == -1)
    {
        fprintf(stderr, "wait: waitpid(WNOHANG) failed: %s\n", strerror(errno));
        return;
    }
    if (poll_result == 0)
        printf("wait: waitpid(..., WNOHANG) saw no exited child yet\n");

    if (waitpid(child_poll, &status, 0) == -1)
    {
        fprintf(stderr, "wait: blocking waitpid failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("wait(waitpid)", status);

    pid_t child_waitid = fork();
    if (child_waitid == -1)
    {
        fprintf(stderr, "wait: fork child_waitid failed: %s\n", strerror(errno));
        return;
    }
    if (child_waitid == 0)
        raise(SIGTERM);

    siginfo_t info;
    memset(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)child_waitid, &info, WEXITED) == -1)
    {
        fprintf(stderr, "wait: waitid failed: %s\n", strerror(errno));
        return;
    }
    printf("wait: waitid() reported pid=%ld uid=%ld code=%d status=%d\n",
           (long)info.si_pid, (long)info.si_uid, info.si_code, info.si_status);

    pid_t child_wait4 = fork();
    if (child_wait4 == -1)
    {
        fprintf(stderr, "wait: fork child_wait4 failed: %s\n", strerror(errno));
        return;
    }
    if (child_wait4 == 0)
    {
        volatile unsigned long long sum = 0;
        for (unsigned long long i = 0; i < 20000000ULL; ++i)
            sum += i;
        (void)sum;
        _exit(10);
    }

    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    if (wait4(child_wait4, &status, 0, &usage) == -1)
    {
        fprintf(stderr, "wait: wait4 failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("wait(wait4)", status);
    printf("wait(wait4): utime=%ld.%06lds  stime=%ld.%06lds\n",
           (long)usage.ru_utime.tv_sec, (long)usage.ru_utime.tv_usec,
           (long)usage.ru_stime.tv_sec, (long)usage.ru_stime.tv_usec);
    printf("wait(wait4): minor faults=%ld  voluntary switches=%ld\n",
           usage.ru_minflt, usage.ru_nvcsw);
}

/*
    Demo 6: system() runs a shell command.

    This is convenient but unsafe for privileged programs because the shell and environment become part of the attack surface.
*/
static void demo_system_call(void)
{
    printf("\n------ 6. system(): synchronous shell execution ------\n");

    int rc = system("printf 'system(): ran through /bin/sh -c\\n'");
    if (rc == -1)
    {
        fprintf(stderr, "system: system() failed: %s\n", strerror(errno));
        return;
    }

    printf("system: raw status = %d\n", rc);
    if (WIFEXITED(rc))
        printf("system: shell command exit status = %d\n", WEXITSTATUS(rc));
    else if (WIFSIGNALED(rc))
        printf("system: shell command died from signal %d\n", WTERMSIG(rc));

    printf("system: prefer execve() with a controlled argv/envp in privileged code\n");
}

/*
    Demo 7: process groups and sessions.

    setpgid() changes job-control grouping.
    setsid() starts a new session and detaches from the caller's previous controlling-terminal association.
*/
static void demo_groups_and_sessions(void)
{
    printf("\n------ 7. Job control structure: setpgid(), getpgid(), setsid() ------\n");
    print_identity("groups(parent)");

    pid_t group_child = fork();
    if (group_child == -1)
    {
        fprintf(stderr, "groups: fork for setpgid() failed: %s\n", strerror(errno));
        return;
    }
    if (group_child == 0)
    {
        if (setpgid(0, 0) == -1)
        {
            fprintf(stderr, "groups(child-setpgid): setpgid failed: %s\n", strerror(errno));
            _exit(1);
        }
        print_identity("groups(child-setpgid)");
        _exit(0);
    }

    int status = 0;
    if (waitpid(group_child, &status, 0) == -1)
    {
        fprintf(stderr, "groups: waitpid for setpgid child failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("groups(setpgid)", status);

    pid_t session_child = fork();
    if (session_child == -1)
    {
        fprintf(stderr, "groups: fork for setsid() failed: %s\n", strerror(errno));
        return;
    }
    if (session_child == 0)
    {
        pid_t sid = setsid();
        if (sid == -1)
        {
            fprintf(stderr, "groups(child-setsid): setsid failed: %s\n", strerror(errno));
            _exit(1);
        }
        printf("groups(child-setsid): setsid() created sid=%ld\n", (long)sid);
        print_identity("groups(child-setsid)");
        _exit(0);
    }

    if (waitpid(session_child, &status, 0) == -1)
    {
        fprintf(stderr, "groups: waitpid for setsid child failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("groups(setsid)", status);
}

/*
    Demo 8: a basic daemonization pattern.

    The child calls setsid() to detach from the parent's session, redirects
    stdin/stdout/stderr to /dev/null, and writes proof-of-life to a log file.
*/
static void demo_daemon_pattern(const char *logfile)
{
    printf("\n------ 8. Daemon pattern: fork(), setsid(), chdir(), redirect stdio ------\n");
    printf("daemon: log file = %s\n", logfile);

    pid_t child = fork();
    if (child == -1)
    {
        fprintf(stderr, "daemon: fork failed: %s\n", strerror(errno));
        return;
    }

    if (child == 0)
    {
        if (setsid() == -1)
            _exit(1);

        if (chdir("/") == -1)
            _exit(1);

        int nullfd = open("/dev/null", O_RDWR);
        if (nullfd == -1)
            _exit(1);

        dup2(nullfd, STDIN_FILENO);
        dup2(nullfd, STDOUT_FILENO);
        dup2(nullfd, STDERR_FILENO);

        if (nullfd > STDERR_FILENO)
            close(nullfd);

        int logfd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (logfd == -1)
            _exit(1);

        char message[256];
        int len = snprintf(message, sizeof(message),
                           "daemon: pid=%ld ppid=%ld sid=%ld cwd=/\n",
                           (long)getpid(), (long)getppid(), (long)getsid(0));
        if (len > 0)
        {
            ssize_t ignored = write(logfd, message, (size_t)len);
            (void)ignored;
        }

        close(logfd);
        _exit(0);
    }

    int status = 0;
    if (waitpid(child, &status, 0) == -1)
    {
        fprintf(stderr, "daemon: waitpid failed: %s\n", strerror(errno));
        return;
    }
    report_wait_status("daemon(parent)", status);
    printf("daemon(parent): child wrote its identity to %s\n", logfile);
}

int main(void)
{
    char daemon_log[PATH_MAX];
    char cwd[PATH_MAX];

    /* Disable stdio buffering so forked children do not replay buffered parent output. */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Starting process-management demonstrations.\n");
    if (ensure_data_dir() == -1)
        return EXIT_FAILURE;
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        fprintf(stderr, "main: getcwd failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (snprintf(daemon_log, sizeof(daemon_log), "%s/data/05-demo_daemon.log", cwd) >= (int)sizeof(daemon_log))
    {
        fprintf(stderr, "main: daemon log path was truncated\n");
        return EXIT_FAILURE;
    }

    demo_process_identity();
    demo_fork_and_inheritance();
    demo_execve();
    demo_exit_variants();
    demo_wait_interfaces();
    demo_system_call();
    demo_groups_and_sessions();
    demo_daemon_pattern(daemon_log);

    printf("\nProcess-management demonstrations complete.\n");
    return EXIT_SUCCESS;
}
