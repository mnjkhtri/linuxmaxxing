#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
    Small Linux signal demonstrations.

    The examples cover:
      - sigaction(): registering a handler, raise() to self
      - sigprocmask(), sigpending(): blocking and querying pending signals
      - SIGCHLD: parent notified when a child exits
      - SA_SIGINFO + sigqueue(): receiving sender PID and integer payload
*/

static volatile sig_atomic_t caught_signo = 0;
static volatile sig_atomic_t child_exited = 0;
static volatile sig_atomic_t info_received = 0;
static volatile sig_atomic_t info_pid = 0;
static volatile sig_atomic_t info_payload = 0;

static void generic_handler(int signo)
{
    caught_signo = (sig_atomic_t)signo;
}

static void chld_handler(int signo)
{
    (void)signo;
    child_exited = 1;
}

static void info_handler(int signo, siginfo_t *si, void *ctx)
{
    (void)signo;
    (void)ctx;
    info_pid = (sig_atomic_t)si->si_pid;
    info_payload = (sig_atomic_t)si->si_value.sival_int;
    info_received = 1;
}

/*
    Demo 1: sigaction() and raise().

    sigaction() is the POSIX replacement for signal() — it offers precise control over handler execution and blocking behaviour.
    raise() sends a signal to the calling process itself,
    suspending execution at the current instruction and running the handler before returning.
*/
static void demo_sigaction(void)
{
    printf("\n------ 1. sigaction(): register handler, raise() to self ------\n");

    struct sigaction sa = {0};
    sa.sa_handler = generic_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    caught_signo = 0;
    raise(SIGUSR1);
    printf("signal: caught %d  (%s)\n", (int)caught_signo,
           strsignal((int)caught_signo));

    sa.sa_handler = SIG_DFL;
    sigaction(SIGUSR1, &sa, NULL);
}

/*
    Demo 2: sigprocmask() and sigpending().

    Blocking a signal defers its delivery — the signal is stored as pending
    rather than interrupting the process. sigpending() lets you inspect what
    is waiting. Unblocking delivers the queued signal immediately.
*/
static void demo_blocking(void)
{
    printf("\n------ 2. Blocking: sigprocmask(), sigpending() ------\n");

    struct sigaction sa = {0};
    sa.sa_handler = generic_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGUSR1, &sa, NULL);

    sigset_t block_mask, pending;
    sigemptyset(&block_mask);
    sigaddset(&block_mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, &block_mask, NULL);

    caught_signo = 0;
    raise(SIGUSR1);

    sigpending(&pending);
    printf("blocking: raised while blocked   pending=%s  caught=%d\n",
           sigismember(&pending, SIGUSR1) ? "yes" : "no", (int)caught_signo);

    sigprocmask(SIG_UNBLOCK, &block_mask, NULL);
    printf("blocking: after unblock          caught=%d  (%s)\n",
           (int)caught_signo, strsignal((int)caught_signo));

    sa.sa_handler = SIG_DFL;
    sigaction(SIGUSR1, &sa, NULL);
}

/*
    Demo 3: SIGCHLD.

    The kernel sends SIGCHLD to the parent when a child terminates. The
    handler sets a flag; the main loop calls waitpid() to reap the zombie.
*/
static void demo_sigchld(void)
{
    printf("\n------ 3. SIGCHLD: parent notified when child exits ------\n");

    struct sigaction sa = {0};
    sa.sa_handler = chld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGCHLD, &sa, NULL);

    child_exited = 0;
    fflush(stdout);
    pid_t child = fork();
    if (child == 0)
        _exit(42);

    while (!child_exited)
        pause();

    int status;
    waitpid(child, &status, 0);
    printf("sigchld: child %d exited  status=%d\n",
           (int)child, WEXITSTATUS(status));

    sa.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa, NULL);
}

/*
    Demo 4: SA_SIGINFO and sigqueue().

    With SA_SIGINFO the kernel passes a siginfo_t to the handler, exposing
    the sender's PID and any attached payload. sigqueue() extends kill() by
    attaching an integer value to the signal, making it a richer IPC primitive.
*/
static void demo_siginfo(void)
{
    printf("\n------ 4. SA_SIGINFO: sender PID and payload via sigqueue() ------\n");

    struct sigaction sa = {0};
    sa.sa_sigaction = info_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR1, &sa, NULL);

    info_received = 0;
    pid_t parent = getpid();
    fflush(stdout);
    pid_t child = fork();
    if (child == 0)
    {
        union sigval val;
        val.sival_int = 42;
        sigqueue(parent, SIGUSR1, val);
        _exit(0);
    }

    while (!info_received)
        pause();

    wait(NULL);
    printf("siginfo: received SIGUSR1  sender_pid=%d  payload=%d\n",
           (int)info_pid, (int)info_payload);

    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);
}

int main(void)
{
    printf("Starting signal demonstrations.\n");

    demo_sigaction();
    demo_blocking();
    demo_sigchld();
    demo_siginfo();

    printf("\nAll signal demonstrations completed.\n");
    return EXIT_SUCCESS;
}
