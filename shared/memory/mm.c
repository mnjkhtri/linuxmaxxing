// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <gelf.h>
#include <libelf.h>
#include "mm_event.h"
#include "json_writer.h"
#include "mm.skel.h"

/*
 * libbpf loads and verifies mm.bpf.o, attaches the phase_boundary entry/return probes, and polls the ring buffer.
 * Each callback serializes one post-phase MM snapshot as a single NDJSON record for the frontend.
 *
 * Stdout carries NDJSON only.
 * Stderr carries machine-readable lifecycle lines (LX_READY / LX_DONE) plus human diagnostics.
 * run.sh can therefore gate the workload on a successful attachment without parsing capture records.
 *
 * The binary event is grouped into event_info/context/state, and the public schema keeps that grouping.
 * event_info.phase_seq authoritatively identifies the workload phase whose boundary produced this snapshot.
 * context describes the workload task the probe ran as; state holds the captured mm_struct/RSS/VMA facts.
 * Serialization is owned here.
 * schema_version, experiment, kind, source, and seq come from the loader.
 * Representation choices such as "0x..."/null and derived page-table summaries are normalized here.
 * Kernel pointers are identities used to connect objects in the visualization, never addresses to dereference.
 * The page-table and XArray observations are bounded and best-effort; the derived counts summarize those bounds.
 */

#define WORKLOAD_PATH "/mnt/host/memory/workload_mm"

static unsigned int record_count;
static unsigned int seq_counter;

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

static unsigned long long elf_symbol_file_offset(const char *path, const char *wanted)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return 0;

	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;

	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf)
	{
		close(fd);
		return 0;
	}

	GElf_Ehdr ehdr;
	unsigned long long value = 0;
	if (!gelf_getehdr(elf, &ehdr))
		goto out;

	Elf_Scn *section = NULL;
	while ((section = elf_nextscn(elf, section)) != NULL && !value)
	{
		GElf_Shdr shdr;
		if (!gelf_getshdr(section, &shdr))
			continue;
		if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
			continue;

		Elf_Data *data = elf_getdata(section, NULL);
		if (!data)
			continue;

		size_t symbols = shdr.sh_size / shdr.sh_entsize;
		for (size_t i = 0; i < symbols; i++)
		{
			GElf_Sym symbol;
			if (!gelf_getsym(data, (int)i, &symbol))
				continue;
			const char *name = elf_strptr(elf, shdr.sh_link, symbol.st_name);
			if (name && strcmp(name, wanted) == 0)
			{
				value = symbol.st_value;
				break;
			}
		}
	}

	if (!value)
		goto out;

	size_t phnum = 0;
	if (elf_getphdrnum(elf, &phnum) != 0)
		goto out;
	for (size_t i = 0; i < phnum; i++)
	{
		GElf_Phdr phdr;
		if (!gelf_getphdr(elf, (int)i, &phdr) || phdr.p_type != PT_LOAD)
			continue;
		if (value >= phdr.p_vaddr && value < phdr.p_vaddr + phdr.p_memsz)
		{
			value = phdr.p_offset + (value - phdr.p_vaddr);
			goto out;
		}
	}
	value = 0;

out:
	elf_end(elf);
	close(fd);
	return value;
}

/*
 * First NDJSON record.
 * The frontend recognizes kind=meta and does not treat it as a snapshot.
 * Static sampling limits live here once instead of on every record.
 */
static void write_meta(struct json_writer *jw)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "memory");
	json_string(jw, "kind", "meta");
	json_string(jw, "source", "ebpf");
	json_string(jw, "clock", "monotonic");
	json_string(jw, "capture", "mm_phase_snapshot");
	json_u32(jw, "max_vmas", MAX_VMAS);
	json_u32(jw, "max_pages_per_vma", MAX_PAGES_PER_VMA);
	json_u32(jw, "max_xarray_scan_slots", MAX_XARRAY_SCAN_SLOTS);
	json_u32(jw, "max_xarray_depth", MAX_XARRAY_DEPTH);
	json_u32(jw, "max_cache_orders", MAX_CACHE_ORDERS);
	json_object_end(jw);
	json_newline(jw);
}

/*
 * The event is one workload phase boundary, so event_info identifies the completed phase.
 * The sequence is the authoritative link to the workload's own phase record.
 */
static void write_event_info(struct json_writer *jw, const struct mm_event_info *event_info)
{
	json_u32(jw, "phase_seq", event_info->phase_seq);
}

/* The workload task the probe executed as; this is where/as whom, not the captured mm itself. */
static void write_context(struct json_writer *jw, const struct mm_context *context)
{
	json_u32(jw, "cpu", context->cpu);
	json_u32(jw, "pid", context->pid);
	json_u32(jw, "tid", context->tid);
	json_string_n(jw, "comm", context->comm, sizeof(context->comm));
}

/* RSS counters observed on mm->rss_stat; signed because the kernel may transiently undercount. */
static void write_rss(struct json_writer *jw, const struct mm_state *state)
{
	json_object_begin_field(jw, "rss");
	json_i64(jw, "anon_pages", state->anon_pages);
	json_i64(jw, "file_pages", state->file_pages);
	json_i64(jw, "shmem_pages", state->shmem_pages);
	json_i64(jw, "swap_entries", state->swap_entries);
	json_object_end(jw);
}

/* Bounded folio observations from the address_space XArray scan, including order buckets. */
static void write_file_cache(struct json_writer *jw, const struct mm_vma_record *vma)
{
	json_object_begin_field(jw, "file_cache");
	json_u32(jw, "folios", vma->cache_folios);
	json_u32(jw, "clean_folios", vma->cache_clean_folios);
	json_u32(jw, "dirty_folios", vma->cache_dirty_folios);
	json_u32(jw, "writeback_folios", vma->cache_writeback_folios);
	json_u32(jw, "lru_folios", vma->cache_lru_folios);
	json_u32(jw, "active_folios", vma->cache_active_folios);
	json_u32(jw, "referenced_folios", vma->cache_referenced_folios);
	json_u32(jw, "workingset_folios", vma->cache_workingset_folios);
	json_u32(jw, "unevictable_folios", vma->cache_unevictable_folios);

	json_array_begin_field(jw, "order_buckets");
	for (unsigned int order = 0; order < MAX_CACHE_ORDERS; order++)
	{
		json_object_begin(jw);
		json_u32(jw, "order", order);
		json_u32(jw, "pages_per_folio", 1U << order);
		json_u32(jw, "folios", vma->cache_order_folios[order]);
		json_u32(jw, "dirty", vma->cache_order_dirty[order]);
		json_object_end(jw);
	}
	json_array_end(jw);
	json_object_end(jw);
}

/* File backing facts; emitted as null when the VMA has no struct file. */
static void write_file_backing(struct json_writer *jw, const struct mm_vma_record *vma)
{
	if (!vma->struct_file)
	{
		json_null(jw, "file");
		return;
	}

	json_object_begin_field(jw, "file");
	json_string_n(jw, "name", vma->file_name, sizeof(vma->file_name));
	json_u64(jw, "inode", vma->inode);
	json_u32(jw, "device", vma->device);
	json_ptr(jw, "mapping", vma->mapping);
	json_u64(jw, "cache_pages", vma->cache_pages);
	json_object_end(jw);
}

/*
 * Bounded page-table sample with userspace-derived summaries.
 * The summary counts are deterministic summaries of the raw arrays, never separate kernel observations.
 * The compact target identity is the same xor-folded PFN encoding the walker produces, masked to its 14 bits.
 */
static void write_page_table(struct json_writer *jw, const struct mm_vma_record *vma)
{
	unsigned int present_pages = 0;
	unsigned int none_pages = 0;
	unsigned int swap_pages = 0;
	unsigned int huge_pmd_pages = 0;
	unsigned int huge_pmd_entries = 0;
	unsigned int huge_pud_pages = 0;
	unsigned int huge_pud_entries = 0;
	unsigned int dirty_entries = 0;
	unsigned char previous = 255;

	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
	{
		unsigned char state = vma->pt_states[page];
		unsigned int dirty = (vma->pt_dirty[page >> 6] >> (page & 63)) & 1ULL;

		if (state == MM_PAGE_PTE)
		{
			present_pages++;
			dirty_entries += dirty;
		}
		else if (state == MM_PAGE_SWAP)
			swap_pages++;
		else if (state == MM_PAGE_HUGE_PMD)
		{
			unsigned long long address = vma->start + (unsigned long long)page * 4096;
			int first_huge_slot = previous != MM_PAGE_HUGE_PMD || page == 0 || !(address & ((1ULL << 21) - 1));

			present_pages++;
			huge_pmd_pages++;
			if (first_huge_slot)
			{
				huge_pmd_entries++;
				dirty_entries += dirty;
			}
		}
		else if (state == MM_PAGE_HUGE_PUD)
		{
			unsigned long long address = vma->start + (unsigned long long)page * 4096;
			int first_huge_slot = previous != MM_PAGE_HUGE_PUD || page == 0 || !(address & ((1ULL << 30) - 1));

			present_pages++;
			huge_pud_pages++;
			if (first_huge_slot)
			{
				huge_pud_entries++;
				dirty_entries += dirty;
			}
		}
		else
			none_pages++;
		previous = state;
	}

	json_object_begin_field(jw, "page_table");
	json_u32(jw, "scanned_pages", vma->pt_scanned_pages);
	json_u32(jw, "present_pages", present_pages);
	json_u32(jw, "none_pages", none_pages);
	json_u32(jw, "swap_pages", swap_pages);
	json_u32(jw, "huge_pmd_pages", huge_pmd_pages);
	json_u32(jw, "huge_pmd_entries", huge_pmd_entries);
	json_u32(jw, "huge_pud_pages", huge_pud_pages);
	json_u32(jw, "huge_pud_entries", huge_pud_entries);
	json_u32(jw, "dirty_entries", dirty_entries);

	json_array_begin_field(jw, "pages");
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
		json_u32_value(jw, vma->pt_states[page]);
	json_array_end(jw);

	json_array_begin_field(jw, "dirty");
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
		json_u32_value(jw, (vma->pt_dirty[page >> 6] >> (page & 63)) & 1ULL);
	json_array_end(jw);

	json_array_begin_field(jw, "targets");
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
		json_u32_value(jw, vma->pt_targets[page] & 0x3fff);
	json_array_end(jw);

	json_object_end(jw);
}

static void write_vma(struct json_writer *jw, const struct mm_vma_record *vma)
{
	json_object_begin(jw);

	json_object_begin_field(jw, "range");
	json_hex(jw, "start", vma->start);
	json_hex(jw, "end", vma->end);
	json_u64(jw, "pgoff", vma->pgoff);
	json_object_end(jw);

	json_hex(jw, "flags", vma->flags);

	json_object_begin_field(jw, "anon_vma");
	json_ptr(jw, "address", vma->anon_vma);
	json_ptr(jw, "root", vma->anon_vma_root);
	json_ptr(jw, "parent", vma->anon_vma_parent);
	json_object_end(jw);

	write_file_backing(jw, vma);
	write_file_cache(jw, vma);
	write_page_table(jw, vma);

	json_object_end(jw);
}

static void write_mm_state(struct json_writer *jw, const struct mm_state *state)
{
	json_object_begin_field(jw, "mm");
	json_ptr(jw, "address", state->mm);
	json_ptr(jw, "mmap_base", state->mmap_base);

	json_object_begin_field(jw, "accounting");
	json_u64(jw, "total_vm", state->total_vm);
	json_u64(jw, "data_vm", state->data_vm);
	json_u64(jw, "exec_vm", state->exec_vm);
	json_u64(jw, "stack_vm", state->stack_vm);
	json_u64(jw, "pgtables_bytes", state->pgtables_bytes);
	json_object_end(jw);

	write_rss(jw, state);

	json_u32(jw, "map_count", state->map_count);
	json_u32(jw, "vma_count", state->vma_count);
	json_object_end(jw);

	json_array_begin_field(jw, "vmas");
	for (unsigned int i = 0; i < state->vma_count && i < MAX_VMAS; i++)
		write_vma(jw, &state->vmas[i]);
	json_array_end(jw);
}

static void write_snapshot(struct json_writer *jw, const struct mm_event *event, unsigned int seq)
{
	json_object_begin(jw);
	json_u32(jw, "schema_version", 1);
	json_string(jw, "experiment", "memory");
	json_string(jw, "kind", "snapshot");
	json_string(jw, "source", "ebpf");
	json_u32(jw, "seq", seq);
	json_u64(jw, "time_ns", event->time_ns);

	json_object_begin_field(jw, "event_info");
	write_event_info(jw, &event->event_info);
	json_object_end(jw);

	json_object_begin_field(jw, "context");
	write_context(jw, &event->context);
	json_object_end(jw);

	json_object_begin_field(jw, "state");
	write_mm_state(jw, &event->state);
	json_object_end(jw);

	json_object_end(jw);
	json_newline(jw);
}

/*
 * libbpf invokes this after the return probe emits one event.
 * Rejecting a short record protects the byte-for-byte ABI shared with struct mm_event in mm_event.h.
 * seq is assigned here in output order; the ring-buffer callback preserves snapshot order.
 */
static int handle_event(void *ctx, void *data, size_t len)
{
	const struct mm_event *event = data;
	struct json_writer jw;

	(void)ctx;

	if (len < sizeof(*event))
		return 0;

	seq_counter++;
	record_count++;

	json_writer_init(&jw, stdout);
	write_snapshot(&jw, event, seq_counter);
	return 0;
}

int main(void)
{
	struct mm_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct bpf_link *entry_link = NULL;
	struct bpf_link *return_link = NULL;
	int err = 0;
	LIBBPF_OPTS(bpf_uprobe_opts, entry_options);
	LIBBPF_OPTS(bpf_uprobe_opts, return_options);

	entry_options.retprobe = false;
	return_options.retprobe = true;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);

	/* Stdout is NDJSON; line-buffer so records reach the capture promptly. */
	setvbuf(stdout, NULL, _IOLBF, 0);

	skel = mm_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "mm: failed to open MM BPF skeleton\n");
		return 1;
	}
	unsigned long long page_offset_base = symbol_address("/proc/kallsyms", "page_offset_base");
	if (!page_offset_base)
	{
		fprintf(stderr, "mm: failed to resolve x86 page-table layout symbols\n");
		err = 1;
		goto out;
	}
	skel->rodata->page_offset_base_address = page_offset_base;
	if (mm_bpf__load(skel) != 0)
	{
		fprintf(stderr, "mm: failed to load MM BPF skeleton\n");
		err = 1;
		goto out;
	}
	unsigned long long phase_offset = elf_symbol_file_offset(WORKLOAD_PATH, "phase_boundary");
	if (!phase_offset)
	{
		fprintf(stderr, "mm: failed to resolve phase_boundary symbol file offset in %s\n", WORKLOAD_PATH);
		err = 1;
		goto out;
	}
	fprintf(stderr, "mm: attaching phase boundary probes at %s + 0x%llx\n", WORKLOAD_PATH, phase_offset);
	entry_link = bpf_program__attach_uprobe_opts(skel->progs.phase_boundary_entry, -1, WORKLOAD_PATH, phase_offset, &entry_options);
	if (!entry_link)
	{
		fprintf(stderr, "mm: failed to attach phase boundary entry uprobe: %d\n", -errno);
		err = 1;
		goto out;
	}
	return_link = bpf_program__attach_uprobe_opts(skel->progs.snapshot_phase_return, -1, WORKLOAD_PATH, phase_offset, &return_options);
	if (!return_link)
	{
		fprintf(stderr, "mm: failed to attach phase boundary return uprobe: %d\n", -errno);
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "mm: failed to create ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	/* Metadata first: static capture facts, not a snapshot. */
	struct json_writer jw;

	json_writer_init(&jw, stdout);
	write_meta(&jw);
	fflush(stdout);

	fprintf(stderr, "LX_READY experiment=memory observer=mm\n");

	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
			break;
	}
	while (ring_buffer__consume(ringbuf) > 0)
		;
	err = 0;

out:
	ring_buffer__free(ringbuf);
	bpf_link__destroy(entry_link);
	bpf_link__destroy(return_link);
	mm_bpf__destroy(skel);

	if (err)
		return 1;
	fprintf(stderr, "LX_DONE experiment=memory observer=mm records=%u\n", record_count);
	return 0;
}
