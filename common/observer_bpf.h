/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LAB_OBSERVER_BPF_H
#define LAB_OBSERVER_BPF_H

/* These counters are read from the skeleton BSS before it is destroyed. */
unsigned long long lab_dropped;
unsigned long long lab_failures;

static __always_inline long lab_output(void *map, void *data, __u64 size, __u64 flags)
{
    long result = bpf_ringbuf_output(map, data, size, flags);
    if (result)
        __sync_fetch_and_add(&lab_dropped, 1);
    return result;
}

static __always_inline long lab_map_update(void *map, const void *key, const void *value, __u64 flags)
{
    long result = bpf_map_update_elem(map, key, value, flags);
    if (result)
        __sync_fetch_and_add(&lab_failures, 1);
    return result;
}
#endif
