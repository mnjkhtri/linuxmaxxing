#include <stdbool.h>
#include <signal.h>
#include <libgen.h>
#include <sys/wait.h>
#include "../../hyperupcall.h"

#include "ept_fault.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dirent.h>
#include <ctype.h>
#include <limits.h>

#define KVM_KO_PATH "/home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm.ko"
#define KVM_INTEL_KO_PATH "/home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm-intel.ko"

long hyperupcall_slot, bypass_alloc_prog_slot, remap_prog_slot, pfn_cache_slot, sp_headers_slot;
long counter_slot, l1_memslots_base_gfns_slot, l1_memslots_npages_slot, l1_memslots_userspace_addr_slot;
long l1_memslots_flags_slot, no_map_list_slot, remap_list_slot;
unsigned long long *counter_map = MAP_FAILED;
unsigned long long *data_map = MAP_FAILED;
unsigned long long *l1_memslots_base_gfns = MAP_FAILED;
unsigned long long *l1_memslots_npages = MAP_FAILED;
unsigned long long *l1_memslots_userspace_addr = MAP_FAILED;
unsigned long long *l1_memslots_flags_addr = MAP_FAILED;
unsigned long long *no_map_list_addr = MAP_FAILED;
unsigned long long *remap_list_addr = MAP_FAILED;

static int dbg_last_pid_report = -2;
static int dbg_last_scan_pid = -2;
static int dbg_last_nomatch_pid = -2;


static int find_l2_vmm_pid(void) {
    DIR *proc;
    struct dirent *de;
    int best_pid = -1;

    proc = opendir("/proc");
    if (!proc)
        return -1;

    while ((de = readdir(proc)) != NULL) {
        char exe_path[64];
        char exe_target[PATH_MAX];
        ssize_t n;
        int pid;
        char *p;

        p = de->d_name;
        if (!isdigit((unsigned char)*p))
            continue;
        while (*p) {
            if (!isdigit((unsigned char)*p))
                goto next_entry;
            p++;
        }

        pid = atoi(de->d_name);
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        n = readlink(exe_path, exe_target, sizeof(exe_target) - 1);
        if (n < 0)
            goto next_entry;

        exe_target[n] = '\0';

        if (strcmp(exe_target, "/opt/kata/bin/qemu-system-x86_64") == 0) {
            if (pid > best_pid)
                best_pid = pid;
        }

next_entry:
        ;
    }

    closedir(proc);
    return best_pid;
}

static int populate_l1_memslot_maps_from_pid(int pid) {
    char maps_path[64];
    char line[1024];
    char perms[8];
    unsigned long start, end;
    unsigned long best_start = 0, best_len = 0;
    unsigned long fallback_start = 0, fallback_len = 0;
    FILE *fp;

    memset(l1_memslots_base_gfns, 0, PAGE_SIZE);
    memset(l1_memslots_npages, 0, PAGE_SIZE);
    memset(l1_memslots_userspace_addr, 0, PAGE_SIZE);

    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    if (pid != dbg_last_scan_pid) {
        printf("DBG: scanning %s\n", maps_path);
        fflush(stdout);
        dbg_last_scan_pid = pid;
    }

    fp = fopen(maps_path, "r");
    if (!fp) {
        if (pid != dbg_last_nomatch_pid) {
            printf("DBG: fopen failed for %s\n", maps_path);
            fflush(stdout);
            dbg_last_nomatch_pid = pid;
        }
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3)
            continue;

        if (perms[0] != 'r' || perms[1] != 'w')
            continue;

        unsigned long len = end - start;

        if (len > fallback_len) {
            fallback_len = len;
            fallback_start = start;
        }

        if (len < (256UL << 20))
            continue;

        if (strstr(line, "memfd:") ||
            strstr(line, "/dev/shm") ||
            strstr(line, "/hugepages") ||
            strstr(line, "guest_mem") ||
            strstr(line, "deleted")) {
            if (len > best_len) {
                best_len = len;
                best_start = start;
            }
        }
    }

    fclose(fp);

    if (best_start == 0 && fallback_len >= (1UL << 30)) {
        best_start = fallback_start;
        best_len = fallback_len;
    }

    if (best_start == 0) {
        if (pid != dbg_last_nomatch_pid) {
            printf("DBG: no memslot candidate for pid=%d best_start=0x%lx best_len=0x%lx fallback_start=0x%lx fallback_len=0x%lx\n",
                   pid, best_start, best_len, fallback_start, fallback_len);
            fflush(stdout);
            dbg_last_nomatch_pid = pid;
        }
        return -1;
    }

    l1_memslots_base_gfns[0] = 0;
    l1_memslots_npages[0] = best_len >> 12;
    l1_memslots_userspace_addr[0] = best_start;

    __sync_synchronize();

    dbg_last_nomatch_pid = -2;

    printf("L1 memslot[0]: base_gfn=%llu npages=%llu userspace_addr=0x%llx\n",
           l1_memslots_base_gfns[0],
           l1_memslots_npages[0],
           l1_memslots_userspace_addr[0]);
    fflush(stdout);

    return 0;
}

void sigint_handler(int sig_num) {
    system("rmmod kvm-intel");
    wait(NULL);
    system("rmmod kvm");
    wait(NULL);
    hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
    hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, l1_memslots_npages);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_userspace_addr_slot, l1_memslots_userspace_addr);
    hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_flags_slot, l1_memslots_flags_addr);
    hyperupcall_unmap_map(hyperupcall_slot, no_map_list_slot, no_map_list_addr);
    hyperupcall_unmap_map(hyperupcall_slot, remap_list_slot, remap_list_addr);
    unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
    unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
    unload_hyperupcall(hyperupcall_slot);
    system("insmod /home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm.ko");
    system("insmod /home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm-intel.ko async_hyperupcall_cache_fill=N");
    exit(0);
}

int main() {
    unload_hyperupcall(0);
    system("rmmod kvm-intel");
    wait(NULL);
    system("rmmod kvm");
    wait(NULL);
    char path[2048];
    char *dir_path;
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (len != -1) {
        path[len] = '\0';
        printf("Executable path: %s\n", path);

        // Get the directory path
        dir_path = dirname(path);
        printf("Directory path: %s\n", dir_path);
    } else {
        printf("Failed to get executable path\n");
    }
    strcpy(path, dir_path);
    strcat(path, "/ept_fault.bpf.o");
    printf("Loading hyperupcall from %s\n", path);
    hyperupcall_slot = load_hyperupcall(path);
    if (hyperupcall_slot < 0) {
        printf("Failed to load hyperupcall\n");
        return -1;
    }
    bypass_alloc_prog_slot = link_hyperupcall(hyperupcall_slot, "bypass_alloc_bpf\0", 1, 0);
    if (bypass_alloc_prog_slot < 0) {
        printf("Failed to link hyperupcall bypass_alloc_prog_slot\n");
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    remap_prog_slot = link_hyperupcall(hyperupcall_slot, "update_mapping\0", 1, 1);
    if (remap_prog_slot < 0) {
        printf("Failed to link hyperupcall\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    pfn_cache_slot = hyperupcall_map_map(hyperupcall_slot, "pfn_cache\0", PFN_CACHE_SIZE*2*sizeof(unsigned long long), (void **)&data_map);
    if (pfn_cache_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    counter_slot = hyperupcall_map_map(hyperupcall_slot, "counter\0", PAGE_SIZE, (void **)&counter_map);
    if (counter_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    l1_memslots_base_gfns_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_base_gfns\0", PAGE_SIZE, (void **)&l1_memslots_base_gfns);
    if (l1_memslots_base_gfns_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    l1_memslots_npages_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_npages\0", PAGE_SIZE, (void **)&l1_memslots_npages);
    if (l1_memslots_npages_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
        hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    l1_memslots_userspace_addr_slot = hyperupcall_map_map(hyperupcall_slot, "l1_memslots_userspace_addr\0", PAGE_SIZE, (void **)&l1_memslots_userspace_addr);
    if (l1_memslots_userspace_addr_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, l1_memslots_npages);
        hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    no_map_list_slot = hyperupcall_map_map(hyperupcall_slot, "no_map_list\0", PAGE_SIZE, (void **)&no_map_list_addr);
    if (no_map_list_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, l1_memslots_npages);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_userspace_addr_slot, l1_memslots_userspace_addr);
        hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    remap_list_slot = hyperupcall_map_map(hyperupcall_slot, "remap_list\0", PAGE_SIZE, (void **)&remap_list_addr);
    if (remap_list_slot < 0) {
        printf("Failed to map map\n");
        unlink_hyperupcall(hyperupcall_slot, bypass_alloc_prog_slot);
        unlink_hyperupcall(hyperupcall_slot, remap_prog_slot);
        hyperupcall_unmap_map(hyperupcall_slot, pfn_cache_slot, data_map);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_base_gfns_slot, l1_memslots_base_gfns);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_npages_slot, l1_memslots_npages);
        hyperupcall_unmap_map(hyperupcall_slot, l1_memslots_userspace_addr_slot, l1_memslots_userspace_addr);
        hyperupcall_unmap_map(hyperupcall_slot, no_map_list_slot, no_map_list_addr);
        hyperupcall_unmap_map(hyperupcall_slot, counter_slot, counter_map);
        unload_hyperupcall(hyperupcall_slot);
        return -1;
    }

    counter_map[PFN_CACHE_SIZE_KEY] = PFN_CACHE_SIZE;
    counter_map[BYPASS_ALLOC_ENABLE] = 0;

    printf("got ptrs: %p %p\n", data_map, counter_map);
    signal(SIGINT, sigint_handler);

    system("insmod /home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm.ko");
    system("insmod /home/ubuntu/shared_folder/hucvisor-linux/arch/x86/kvm/kvm-intel.ko async_hyperupcall_cache_fill=N");

    printf("starting loop\n");
    fflush(stdout);

    int last_pid = -1;

    while (true) {
        int pid = find_l2_vmm_pid();

        if (pid > 0 && (pid != last_pid || l1_memslots_npages[0] == 0)) {
            if (populate_l1_memslot_maps_from_pid(pid) == 0) {
                __sync_synchronize();
                counter_map[BYPASS_ALLOC_ENABLE] = 1;
                printf("DBG: enabled bypass for pid=%d\n", pid);
                fflush(stdout);
                last_pid = pid;
            } else {
                counter_map[BYPASS_ALLOC_ENABLE] = 0;
                last_pid = -1;
            }
        } else if (pid <= 0) {
           // if (last_pid != -1 || counter_map[BYPASS_ALLOC_ENABLE] != 0) {
               // printf("DBG: disabling bypass because no L2 pid is present\n");
              //  fflush(stdout);
            //}
            //counter_map[BYPASS_ALLOC_ENABLE] = 0;
            //last_pid = -1;
            //memset(l1_memslots_base_gfns, 0, PAGE_SIZE);
            //memset(l1_memslots_npages, 0, PAGE_SIZE);
          //  memset(l1_memslots_userspace_addr, 0, PAGE_SIZE);
        }

        usleep(200000);
    }

    return 0;
}
