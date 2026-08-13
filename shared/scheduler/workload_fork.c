#define _GNU_SOURCE

#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHILDREN 25
#define DEFAULT_SECONDS 10

/*
 * Create repeatable but varied scheduler pressure for both observers in run.sh.
 * Twenty-five children are released together, named schedNNN, and assigned different positive nice values. Some periodically sleep or yield; the rest stay CPU-bound.
 * This exposes forks, wakeups, context switches, per-CPU CFS tree changes, and cross-CPU movement in one experiment.
 *
 * The observers do not filter on schedNNN. Kernel workers, the shell, idle tasks, and any other task involved in the interval remain truthful parts of the scheduler story.
 */
static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

int main(int argc, char **argv)
{
	int seconds = DEFAULT_SECONDS;
	int pipes[CHILDREN][2];
	pid_t pids[CHILDREN];
	int i;

	if (argc > 1)
	{
		seconds = atoi(argv[1]);
		if (seconds <= 0)
			seconds = DEFAULT_SECONDS;
	}

	printf("starting workload with %d children for %d seconds\n", CHILDREN, seconds);
	printf("children are scheduler-balanced and named schedNNN for scheduler hooks\n");
	fflush(stdout);

	/* A private pipe holds every child behind the same start barrier. */
	for (i = 0; i < CHILDREN; i++)
	{
		if (pipe(pipes[i]) != 0)
		{
			perror("pipe");
			exit(1);
		}

		pids[i] = fork();
		if (pids[i] < 0)
		{
			perror("fork");
			exit(1);
		}

		if (pids[i] == 0)
		{
			char byte;
			char name[16];
			struct timespec ts;
			long long end;
			unsigned int loops = 120000U + (unsigned int)(i % 17) * 35000U;
			unsigned int iter = 0;

			close(pipes[i][1]);
			signal(SIGTERM, on_signal);
			signal(SIGINT, on_signal);

			snprintf(name, sizeof(name), "sched%03d", i);
			if (prctl(PR_SET_NAME, name, 0, 0, 0) != 0)
			{
				perror("prctl(PR_SET_NAME)");
				_exit(1);
			}

			/* Positive nice values need no privileges and create varied CFS weights. */
			if (setpriority(PRIO_PROCESS, 0, i % 20) != 0)
				perror("setpriority");

			if (read(pipes[i][0], &byte, 1) != 1)
				_exit(1);
			close(pipes[i][0]);

			if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
			{
				perror("clock_gettime");
				_exit(1);
			}
			end = ((long long)ts.tv_sec * 1000000000LL + ts.tv_nsec) +
				  (long long)seconds * 1000000000LL;

			while (!stop)
			{
				volatile unsigned long x = 0;
				long long now;
				unsigned int j;

				if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
					_exit(1);
				now = (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
				if (now >= end)
					break;

				for (j = 0; j < loops; j++)
					x = (x * 1664525UL) + 1013904223UL + j;

				/* Mix blocking, voluntary yielding, and uninterrupted CPU work. */
				if ((i % 10) == 0 && (iter % 8) == 0)
					usleep(1000 + (i % 5) * 700);
				else if ((i % 7) == 0 && (iter % 16) == 0)
					sched_yield();

				iter++;
			}

			_exit(0);
		}

		close(pipes[i][0]);
	}

	printf("children forked; releasing them together\n");
	fflush(stdout);

	/* Releasing all pipes together gives the scheduler a real balancing burst. */
	for (i = 0; i < CHILDREN; i++)
	{
		if (write(pipes[i][1], "x", 1) != 1)
			perror("write start byte");
		close(pipes[i][1]);
	}

	for (i = 0; i < CHILDREN; i++)
		waitpid(pids[i], NULL, 0);

	printf("workload complete\n");
	return 0;
}
