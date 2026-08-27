#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include "../../hyperupcall.h"

static long hyperupcall_slot = -1;
static long program_slot = -1;

static void cleanup(void)
{
    if (program_slot >= 0)
        unlink_hyperupcall(hyperupcall_slot, program_slot);
    if (hyperupcall_slot >= 0)
        unload_hyperupcall(hyperupcall_slot);
}

static void sigint_handler(int sig_num)
{
    (void)sig_num;
    cleanup();
    _exit(0);
}

int main(void)
{
    hyperupcall_slot = load_hyperupcall("./packet_filter_mb.bpf.o");
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }

    program_slot = link_hyperupcall(hyperupcall_slot, "packet_filter_mb\0", 0, NETDEV_INDEX);
    if (program_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    signal(SIGINT, sigint_handler);
    printf("packet_filter_mb running; Ctrl+C to stop\n");
    while (true)
        sleep(1);
    return 0;
}
