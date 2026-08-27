// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <bpf/libbpf.h>
#include "ept_event.h"
#include "json_writer.h"
#include "ept.skel.h"

/*
 * libbpf loads and verifies ept.bpf.o, attaches the KVM boundary programs, and polls the ring buffer.
 * Each callback serializes one post-boundary EPT snapshot as a single NDJSON record for the frontend.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * The public schema preserves the binary event's typed sections: boundary, context, paired request payloads, disposition, and EPT state.
 * Serialization is owned here.
 * schema_version, experiment, kind, source, and seq come from the loader.
 * Representation choices such as readable event names, "0x..."/null pointers, and booleans are normalized here.
 * Kernel pointers are identities used to connect objects in the visualization, never addresses to dereference.
 * The EPT walk is bounded and best-effort; the recorded limits live in the meta record.
 */

static unsigned int record_count;
static unsigned int seq_counter;
static bool vmx_disposition_available;
static bool split_snapshot_available;
static bool mmio_snapshot_available;

static volatile sig_atomic_t exiting;

static void on_signal(int signo)
{
	(void)signo;
	exiting = 1;
}

static unsigned long long symbol_address(const char *path, const char *wanted)
{
	FILE *symbols = fopen(path, "r");

	if (!symbols)
		return 0;
	for (;;)
	{
		unsigned long long address;
		char type;
		char name[256];

		if (fscanf(symbols, "%llx %c %255s", &address, &type, name) != 3)
			break;
		if (strcmp(name, wanted) == 0)
		{
			fclose(symbols);
			return address;
		}
	}
	fclose(symbols);
	return 0;
}

/* The public schema carries readable event names; the binary ABI carries only the integer. */
static const char *event_name(unsigned int event)
{
	switch (event)
	{
	case EPT_EVENT_KVM_ENTRY:
		return "kvm_entry";
	case EPT_EVENT_KVM_EXIT:
		return "kvm_exit";
	case EPT_EVENT_KVM_USERSPACE_EXIT:
		return "kvm_userspace_exit";
	case EPT_EVENT_KVM_UNMAP_HVA_RANGE:
		return "kvm_unmap_hva_range";
	case EPT_EVENT_KVM_MMU_SPTE_REQUESTED:
		return "kvm_mmu_spte_requested";
	case EPT_EVENT_KVM_MMU_SET_SPTE:
		return "kvm_mmu_set_spte";
	case EPT_EVENT_KVM_FLUSH_REMOTE_TLBS:
		return "kvm_flush_remote_tlbs";
	case EPT_EVENT_CONTROL_BEGIN:
		return "control_begin";
	case EPT_EVENT_CONTROL_END:
		return "control_end";
	case EPT_EVENT_MEMSLOT_BEGIN:
		return "memslot_begin";
	case EPT_EVENT_MEMSLOT_END:
		return "memslot_end";
	case EPT_EVENT_SYS_ENTER_IOCTL:
		return "sys_enter_ioctl";
	case EPT_EVENT_SYS_EXIT_IOCTL:
		return "sys_exit_ioctl";
	case EPT_EVENT_VMX_HANDLE_EXIT_RETURN:
		return "vmx_handle_exit_return";
	case EPT_EVENT_KVM_PAGE_FAULT:
		return "kvm_page_fault";
	case EPT_EVENT_KVM_MMU_SPLIT_HUGE_PAGE:
		return "kvm_mmu_split_huge_page";
	case EPT_EVENT_MARK_MMIO_SPTE:
		return "mark_mmio_spte";
	case EPT_EVENT_SYS_ENTER_MADVISE:
		return "sys_enter_madvise";
	case EPT_EVENT_SYS_EXIT_MADVISE:
		return "sys_exit_madvise";
	case EPT_EVENT_SYS_ENTER_MMAP:
		return "sys_enter_mmap";
	case EPT_EVENT_SYS_EXIT_MMAP:
		return "sys_exit_mmap";
	default:
		return "unknown";
	}
}

static const char *ioctl_request_name(unsigned long long request)
{
	switch (request)
	{
	case KVM_GET_API_VERSION: return "KVM_GET_API_VERSION";
	case KVM_CHECK_EXTENSION: return "KVM_CHECK_EXTENSION";
	case KVM_CREATE_VM: return "KVM_CREATE_VM";
	case KVM_SET_USER_MEMORY_REGION: return "KVM_SET_USER_MEMORY_REGION";
	case KVM_CREATE_VCPU: return "KVM_CREATE_VCPU";
	case KVM_GET_VCPU_MMAP_SIZE: return "KVM_GET_VCPU_MMAP_SIZE";
	case KVM_GET_SREGS: return "KVM_GET_SREGS";
	case KVM_SET_SREGS: return "KVM_SET_SREGS";
	case KVM_SET_REGS: return "KVM_SET_REGS";
	case KVM_CLEAR_DIRTY_LOG: return "KVM_CLEAR_DIRTY_LOG";
	case KVM_RUN: return "KVM_RUN";
	default: return "UNKNOWN_IOCTL";
	}
}

static const char *madvise_name(int advice)
{
	switch (advice)
	{
	case MADV_DONTNEED: return "MADV_DONTNEED";
	case MADV_HUGEPAGE: return "MADV_HUGEPAGE";
	default: return "UNKNOWN_ADVICE";
	}
}

static const char *exit_disposition_name(int result)
{
	if (result > 0) return "resume guest";
	if (result == 0) return "return userspace";
	return "error";
}

static bool tracepoint_exists(const char *group, const char *event)
{
	char path[512];

	if (snprintf(path, sizeof(path), "/sys/kernel/tracing/events/%s/%s", group, event) > 0 && access(path, F_OK) == 0)
		return true;
	if (snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/events/%s/%s", group, event) > 0 && access(path, F_OK) == 0)
		return true;
	return false;
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a snapshot.
 * Static sampling limits live here once instead of on every record.
 */
static void write_meta(struct json_writer *jw)
{
	const char *operations[] = {"", "MADV_DONTNEED", "REPLACE_MEMSLOT", "CLEAR_DIRTY_LOG", "INSTALL_HUGE_SLOT", "ENABLE_HUGE_DIRTY_LOG"};

	json_object_begin(jw);
	json_u32(jw, "schema_version", 4);
	json_string(jw, "experiment", "virt-ept");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "ept_snapshot");
	json_u32(jw, "ept_levels", EPT_LEVELS);
	json_u32(jw, "slot0_gfn_samples", SLOT0_GFN_SAMPLES);
	json_u32(jw, "huge_gfn_samples", HUGE_GFN_SAMPLES);
	json_u32(jw, "max_gfn_samples", MAX_GFN_SAMPLES);
	json_u32(jw, "huge_gfn_base", HUGE_GFN_BASE);
	json_u32(jw, "huge_gfn_stride", HUGE_GFN_STRIDE);
	json_u32(jw, "data_gfn", 7);
	json_u32(jw, "mmio_gfn", 10);
	json_u32(jw, "control_port", 0xe9);
	json_bool(jw, "vmx_disposition_available", vmx_disposition_available);
	json_bool(jw, "split_snapshot_available", split_snapshot_available);
	json_bool(jw, "mmio_snapshot_available", mmio_snapshot_available);
	json_array_begin_field(jw, "control_commands");
	for (unsigned int command = 1; command < 6; command++)
	{
		json_object_begin(jw);
		json_u32(jw, "command", command);
		json_string(jw, "operation", operations[command]);
		json_object_end(jw);
	}
	json_array_end(jw);
	json_object_end(jw);
	json_newline(jw);
}

static void write_entry(struct json_writer *jw, const struct ept_entry_record *entry)
{
	json_object_begin(jw);
	json_u32(jw, "level", entry->level);
	json_hex(jw, "table_hpa", entry->table_hpa);
	json_u32(jw, "index", entry->index);
	json_hex(jw, "spte", entry->spte);
	json_bool(jw, "present", entry->present != 0);
	json_bool(jw, "mmio", entry->mmio != 0);
	json_bool(jw, "leaf", entry->leaf != 0);
	json_bool(jw, "r", entry->readable != 0);
	json_bool(jw, "w", entry->writable != 0);
	json_bool(jw, "x", entry->executable != 0);
	json_bool(jw, "a", entry->accessed != 0);
	json_bool(jw, "d", entry->dirty != 0);
	json_object_end(jw);
}

static void write_gfn(struct json_writer *jw, const struct ept_guest_gfn *gfn)
{
	json_object_begin(jw);
	json_u64(jw, "gfn", gfn->gfn);
	json_hex(jw, "gva", gfn->gva);
	json_hex(jw, "gpa", gfn->gpa);
	json_bool(jw, "ept_mapped", gfn->ept_mapped != 0);
	json_bool(jw, "ept_mmio", gfn->ept_mmio != 0);
	json_u32(jw, "leaf_level", gfn->leaf_level);
	json_hex(jw, "leaf_pfn", gfn->leaf_pfn);
	json_array_begin_field(jw, "entries");
	for (unsigned int i = 0; i < EPT_LEVELS; i++)
		write_entry(jw, &gfn->entries[i]);
	json_array_end(jw);
	json_object_end(jw);
}

static void write_control(struct json_writer *jw, const struct ept_control_info *control)
{
	json_object_begin_field(jw, "control");
	json_bool(jw, "present", control->present != 0);
	if (control->present)
	{
		json_bool(jw, "completed", control->completed != 0);
		json_u32(jw, "command", control->command);
		json_u64(jw, "operation_id", control->operation_id);
		json_u64(jw, "duration_ns", control->duration_ns);
		json_i64(jw, "result", control->result);
	}
	json_object_end(jw);
}

static void write_memslot(struct json_writer *jw, const struct ept_memslot_info *memslot)
{
	json_object_begin_field(jw, "memslot");
	json_bool(jw, "present", memslot->present != 0);
	if (memslot->present)
	{
		json_bool(jw, "completed", memslot->completed != 0);
		json_u32(jw, "control_command", memslot->control_command);
		json_i64(jw, "vm_fd", memslot->vm_fd);
		json_u32(jw, "slot", memslot->slot);
		json_hex(jw, "flags", memslot->flags);
		json_hex(jw, "guest_phys_addr", memslot->guest_phys_addr);
		json_ptr(jw, "userspace_addr", memslot->userspace_addr);
		json_hex(jw, "size", memslot->size);
		json_u64(jw, "operation_id", memslot->operation_id);
		json_u64(jw, "duration_ns", memslot->duration_ns);
		json_i64(jw, "result", memslot->result);
	}
	json_object_end(jw);
}

static void write_ioctl(struct json_writer *jw, const struct ept_ioctl_info *ioctl_info)
{
	json_object_begin_field(jw, "ioctl");
	json_bool(jw, "present", ioctl_info->present != 0);
	json_bool(jw, "completed", ioctl_info->completed != 0);
	if (ioctl_info->present)
	{
		json_i64(jw, "fd", ioctl_info->fd);
		json_hex(jw, "request", ioctl_info->request);
		json_string(jw, "request_name", ioctl_request_name(ioctl_info->request));
		json_hex(jw, "argument", ioctl_info->argument);
		json_u64(jw, "call_id", ioctl_info->call_id);
		json_i64(jw, "result", ioctl_info->result);
		json_u64(jw, "duration_ns", ioctl_info->duration_ns);
	}
	json_object_end(jw);
}

static void write_madvise(struct json_writer *jw, const struct ept_madvise_info *madvise)
{
	json_object_begin_field(jw, "madvise");
	json_bool(jw, "present", madvise->present != 0);
	json_bool(jw, "completed", madvise->completed != 0);
	if (madvise->present)
	{
		json_ptr(jw, "start", madvise->start);
		json_hex(jw, "length", madvise->length);
		json_i64(jw, "advice", madvise->advice);
		json_string(jw, "advice_name", madvise_name(madvise->advice));
		json_u64(jw, "call_id", madvise->call_id);
		json_i64(jw, "result", madvise->result);
		json_u64(jw, "duration_ns", madvise->duration_ns);
	}
	json_object_end(jw);
}

static void write_mmap(struct json_writer *jw, const struct ept_mmap_info *mmap_info)
{
	json_object_begin_field(jw, "mmap");
	json_bool(jw, "present", mmap_info->present != 0);
	json_bool(jw, "completed", mmap_info->completed != 0);
	if (mmap_info->present)
	{
		json_ptr(jw, "requested_addr", mmap_info->requested_addr);
		json_hex(jw, "length", mmap_info->length);
		json_hex(jw, "prot", mmap_info->prot);
		json_hex(jw, "flags", mmap_info->flags);
		json_i64(jw, "fd", mmap_info->fd);
		json_hex(jw, "offset", mmap_info->offset);
		json_u64(jw, "call_id", mmap_info->call_id);
		json_ptr(jw, "result_hva", mmap_info->result);
		json_u64(jw, "duration_ns", mmap_info->duration_ns);
	}
	json_object_end(jw);
}

static void write_disposition(struct json_writer *jw, const struct ept_disposition_info *disposition)
{
	json_object_begin_field(jw, "disposition");
	json_bool(jw, "present", disposition->present != 0);
	if (disposition->present)
	{
		json_i64(jw, "result", disposition->result);
		json_string(jw, "meaning", exit_disposition_name(disposition->result));
	}
	json_object_end(jw);
}

static void write_state(struct json_writer *jw, const struct ept_state *state)
{
	json_object_begin_field(jw, "state");
	json_bool(jw, "present", state->present != 0);
	if (state->present)
	{
		json_ptr(jw, "vcpu", state->vcpu);
		json_ptr(jw, "kvm", state->kvm);
		json_ptr(jw, "mmu", state->mmu);
		json_hex(jw, "root_hpa", state->root_hpa);
		json_hex(jw, "root_pgd", state->root_pgd);
		json_array_begin_field(jw, "gfns");
		for (unsigned int i = 0; i < MAX_GFN_SAMPLES; i++)
			write_gfn(jw, &state->gfns[i]);
		json_array_end(jw);
	}
	else
	{
		json_null(jw, "vcpu");
		json_null(jw, "kvm");
		json_null(jw, "mmu");
		json_null(jw, "root_hpa");
		json_null(jw, "root_pgd");
		json_null(jw, "gfns");
	}
	json_object_end(jw);
}

static void write_context(struct json_writer *jw, const struct ept_context *context)
{
	json_object_begin_field(jw, "context");
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_u32(jw, "cpu", context->cpu);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
	json_object_end(jw);
}

static void write_event_info(struct json_writer *jw, const struct ept_event_info *event_info)
{
	json_object_begin_field(jw, "event_info");
	json_u32(jw, "event", event_info->event);
	json_string(jw, "event_name", event_name(event_info->event));
	json_object_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct ept_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 4);
	json_string(jw, "experiment", "virt-ept");
	json_string(jw, "kind", "snapshot");
	json_string(jw, "source", "ebpf");
	json_u32(jw, "seq", seq);
	json_u64(jw, "time_ns", event->time_ns);
	write_event_info(jw, &event->event_info);
	write_context(jw, &event->context);
	write_control(jw, &event->control);
	write_memslot(jw, &event->memslot);
	write_ioctl(jw, &event->ioctl);
	write_madvise(jw, &event->madvise);
	write_mmap(jw, &event->mmap);
	write_disposition(jw, &event->disposition);
	write_state(jw, &event->state);
	json_object_end(jw);
	json_newline(jw);
}

/*
 * libbpf invokes this for every KVM boundary snapshot emitted by the BPF program.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct ept_event in ept_event.h.
 * seq is assigned here in output order; the ring-buffer callback preserves snapshot order.
 */
static int handle_event(void *context, void *data, size_t length)
{
	const struct ept_event *event = data;
	struct json_writer jw;

	(void)context;

	if (length < sizeof(*event))
		return 0;

	seq_counter++;
	record_count++;

	json_writer_init(&jw, stdout);
	write_snapshot(&jw, event, seq_counter);
	return json_writer_ok(&jw) ? 0 : -1;
}

int main(void)
{
	struct ept_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	int err = 0;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Stdout is NDJSON; line-buffer so records reach the capture promptly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = ept_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "ept: failed to open EPT BPF skeleton\n");
		return 1;
	}
	unsigned long long page_offset_base = symbol_address("/proc/kallsyms", "page_offset_base");
	if (!page_offset_base)
	{
		fprintf(stderr, "ept: failed to resolve page_offset_base\n");
		err = 1;
		goto out;
	}
	skel->rodata->page_offset_base_address = page_offset_base;
	vmx_disposition_available = symbol_address("/proc/kallsyms", "vmx_handle_exit") != 0;
	split_snapshot_available = tracepoint_exists("kvmmmu", "kvm_mmu_split_huge_page");
	mmio_snapshot_available = tracepoint_exists("kvmmmu", "mark_mmio_spte");
	if (!vmx_disposition_available)
		bpf_program__set_autoload(skel->progs.observe_vmx_handle_exit_return, false);
	if (!split_snapshot_available)
		bpf_program__set_autoload(skel->progs.kvm_mmu_split_huge_page_snapshot, false);
	if (!mmio_snapshot_available)
		bpf_program__set_autoload(skel->progs.mark_mmio_spte_snapshot, false);
	if (ept_bpf__load(skel) != 0)
	{
		fprintf(stderr, "ept: failed to load EPT BPF skeleton\n");
		err = 1;
		goto out;
	}
	if (ept_bpf__attach(skel) != 0)
	{
		fprintf(stderr, "ept: failed to attach EPT BPF programs\n");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "ept: failed to create ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	/* Metadata first: static capture facts, not a snapshot. */
	struct json_writer jw;

	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);

	fprintf(stderr, "LX_READY experiment=virt-ept observer=ept\n");

	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
		{
			fprintf(stderr, "ept: ring-buffer poll failed: %d\n", err);
			goto out;
		}
	}
	while ((err = ring_buffer__consume(ringbuf)) > 0)
		;
	if (err < 0)
	{
		fprintf(stderr, "ept: ring-buffer consume failed: %d\n", err);
		goto out;
	}
	err = 0;

out:
	ring_buffer__free(ringbuf);
	ept_bpf__destroy(skel);

	if (err)
		return 1;
	fprintf(stderr, "LX_DONE experiment=virt-ept observer=ept records=%u\n", record_count);
	return 0;
}
