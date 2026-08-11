// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <gelf.h>
#include <libelf.h>
#include "mm.skel.h"

#define MAX_VMAS 16
#define MAX_PAGES_PER_VMA 512
#define PT_DIRTY_WORDS ((MAX_PAGES_PER_VMA + 63) / 64)
#define MAX_CACHE_ORDERS 10
#define WORKLOAD_PATH "/mnt/host/_work/build/exercise_memory_management"
#define CAPTURE_DIR "/mnt/host/_captures"
#define CAPTURE_PATH CAPTURE_DIR "/mm.ndjson"

struct vma_record
{
	unsigned long long start;
	unsigned long long end;
	unsigned long long flags;
	unsigned long long pgoff;
	unsigned int struct_file;
	unsigned long long anon_vma;
	unsigned long long anon_vma_root;
	unsigned long long anon_vma_parent;
	unsigned long long inode;
	unsigned int device;
	char file_name[64];
	unsigned long long mapping;
	unsigned long long cache_pages;
	unsigned int cache_folios;
	unsigned short cache_order_folios[MAX_CACHE_ORDERS];
	unsigned short cache_order_dirty[MAX_CACHE_ORDERS];
	unsigned int cache_clean_folios;
	unsigned int cache_dirty_folios;
	unsigned int cache_writeback_folios;
	unsigned int cache_lru_folios;
	unsigned int cache_active_folios;
	unsigned int cache_referenced_folios;
	unsigned int cache_workingset_folios;
	unsigned int cache_unevictable_folios;
	unsigned int pt_scanned_pages;
	unsigned char pt_states[MAX_PAGES_PER_VMA];
	unsigned long long pt_dirty[PT_DIRTY_WORDS];
	unsigned short pt_targets[MAX_PAGES_PER_VMA];
};

struct mm_snapshot
{
	unsigned long long timestamp_ns;
	unsigned long long pid_tgid;
	unsigned long long mm;
	unsigned long long mmap_base;
	unsigned long long total_vm;
	unsigned long long data_vm;
	unsigned long long exec_vm;
	unsigned long long stack_vm;
	unsigned long long pgtables_bytes;
	unsigned int map_count;
	unsigned int vma_count;
	long long anon_pages;
	long long file_pages;
	long long shmem_pages;
	long long swap_entries;
	char comm[16];
	struct vma_record vmas[MAX_VMAS];
};

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

static void json_comma(FILE *output, int *first)
{
	if (*first)
	{
		*first = 0;
		return;
	}
	fputc(',', output);
}

static void json_string_value(FILE *output, const char *value)
{
	fputc('"', output);
	for (size_t i = 0; i < 64 && value[i]; i++)
	{
		unsigned char c = value[i];

		if (c == '"' || c == '\\')
			fprintf(output, "\\%c", c);
		else if (c < 0x20)
			fprintf(output, "\\u%04x", c);
		else
			fputc(c, output);
	}
	fputc('"', output);
}

static void json_string(FILE *output, int *first, const char *name, const char *value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":", name);
	json_string_value(output, value);
}

static void json_u32(FILE *output, int *first, const char *name, unsigned int value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":%u", name, value);
}

static void json_u64(FILE *output, int *first, const char *name, unsigned long long value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":%llu", name, value);
}

static void json_i64(FILE *output, int *first, const char *name, long long value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":%lld", name, value);
}

static void json_hex(FILE *output, int *first, const char *name, unsigned long long value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":\"0x%llx\"", name, value);
}

static void print_page_states(FILE *output, const struct vma_record *vma)
{
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
	{
		if (page)
			fputc(',', output);
		fprintf(output, "%u", vma->pt_states[page]);
	}
}

static void print_page_targets(FILE *output, const struct vma_record *vma)
{
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
	{
		if (page)
			fputc(',', output);
		fprintf(output, "%u", vma->pt_targets[page] & 0x3fff);
	}
}

static void print_page_dirty(FILE *output, const struct vma_record *vma)
{
	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
	{
		if (page)
			fputc(',', output);
		fprintf(output, "%llu", (vma->pt_dirty[page >> 6] >> (page & 63)) & 1ULL);
	}
}

static void print_file_cache(FILE *output, const struct vma_record *vma)
{
	int first = 1;

	fputc('{', output);
	json_u32(output, &first, "folios", vma->cache_folios);
	json_u32(output, &first, "clean_folios", vma->cache_clean_folios);
	json_u32(output, &first, "dirty_folios", vma->cache_dirty_folios);
	json_u32(output, &first, "writeback_folios", vma->cache_writeback_folios);
	json_u32(output, &first, "lru_folios", vma->cache_lru_folios);
	json_u32(output, &first, "active_folios", vma->cache_active_folios);
	json_u32(output, &first, "referenced_folios", vma->cache_referenced_folios);
	json_u32(output, &first, "workingset_folios", vma->cache_workingset_folios);
	json_u32(output, &first, "unevictable_folios", vma->cache_unevictable_folios);
	json_comma(output, &first);
	fputs("\"order_buckets\":[", output);
	for (unsigned int order = 0; order < MAX_CACHE_ORDERS; order++)
	{
		int bucket_first = 1;
		if (order)
			fputc(',', output);
		fputc('{', output);
		json_u32(output, &bucket_first, "order", order);
		json_u32(output, &bucket_first, "pages_per_folio", 1U << order);
		json_u32(output, &bucket_first, "folios", vma->cache_order_folios[order]);
		json_u32(output, &bucket_first, "dirty", vma->cache_order_dirty[order]);
		fputc('}', output);
	}
	fputc(']', output);
	fputc('}', output);
}

static void print_page_table(FILE *output, const struct vma_record *vma)
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
	int first = 1;

	for (unsigned int page = 0; page < vma->pt_scanned_pages && page < MAX_PAGES_PER_VMA; page++)
	{
		unsigned char state = vma->pt_states[page];
		unsigned int dirty = (vma->pt_dirty[page >> 6] >> (page & 63)) & 1ULL;

		if (state == 1)
		{
			present_pages++;
			dirty_entries += dirty;
		}
		else if (state == 2)
			swap_pages++;
		else if (state == 3)
		{
			unsigned long long address = vma->start + (unsigned long long)page * 4096;
			int first_huge_slot = previous != 3 || page == 0 || !(address & ((1ULL << 21) - 1));

			present_pages++;
			huge_pmd_pages++;
			if (first_huge_slot)
			{
				huge_pmd_entries++;
				dirty_entries += dirty;
			}
		}
		else if (state == 4)
		{
			unsigned long long address = vma->start + (unsigned long long)page * 4096;
			int first_huge_slot = previous != 4 || page == 0 || !(address & ((1ULL << 30) - 1));

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

	fputc('{', output);
	json_u32(output, &first, "scanned_pages", vma->pt_scanned_pages);
	json_u32(output, &first, "present_pages", present_pages);
	json_u32(output, &first, "none_pages", none_pages);
	json_u32(output, &first, "swap_pages", swap_pages);
	json_u32(output, &first, "huge_pmd_pages", huge_pmd_pages);
	json_u32(output, &first, "huge_pmd_entries", huge_pmd_entries);
	json_u32(output, &first, "huge_pud_pages", huge_pud_pages);
	json_u32(output, &first, "huge_pud_entries", huge_pud_entries);
	json_u32(output, &first, "dirty_entries", dirty_entries);
	json_comma(output, &first);
	fputs("\"pages\":[", output);
	print_page_states(output, vma);
	fputs("],\"dirty\":[", output);
	print_page_dirty(output, vma);
	fputs("],\"targets\":[", output);
	print_page_targets(output, vma);
	fputs("]}", output);
}

static void print_vma(FILE *output, const struct vma_record *vma)
{
	int first = 1;

	fputc('{', output);
	json_hex(output, &first, "start", vma->start);
	json_hex(output, &first, "end", vma->end);
	json_hex(output, &first, "flags", vma->flags);
	json_u64(output, &first, "pgoff", vma->pgoff);
	json_u32(output, &first, "struct_file", vma->struct_file);
	json_hex(output, &first, "anon_vma", vma->anon_vma);
	json_hex(output, &first, "anon_vma_root", vma->anon_vma_root);
	json_hex(output, &first, "anon_vma_parent", vma->anon_vma_parent);
	json_u32(output, &first, "device", vma->device);
	json_u64(output, &first, "inode", vma->inode);
	json_hex(output, &first, "mapping", vma->mapping);
	json_u64(output, &first, "cache_pages", vma->cache_pages);
	json_comma(output, &first);
	fputs("\"file_cache\":", output);
	print_file_cache(output, vma);
	json_string(output, &first, "file_name", vma->file_name);
	json_comma(output, &first);
	fputs("\"page_table\":", output);
	print_page_table(output, vma);
	fputc('}', output);
}

/* libbpf invokes this once per phase-boundary snapshot emitted by the uprobe. */
static int handle_event(void *ctx, void *data, size_t length)
{
	const struct mm_snapshot *event = data;
	FILE *output = ctx;

	if (length < sizeof(*event))
		return 0;
	unsigned int tgid = event->pid_tgid >> 32;
	unsigned int tid = (unsigned int)event->pid_tgid;
	int first = 1;

	fputc('{', output);
	json_string(output, &first, "type", "mm_snapshot");
	json_u64(output, &first, "time_ns", event->timestamp_ns);
	json_u32(output, &first, "tgid", tgid);
	json_u32(output, &first, "tid", tid);
	json_string(output, &first, "comm", event->comm);
	json_hex(output, &first, "mm", event->mm);
	json_hex(output, &first, "mmap_base", event->mmap_base);
	json_u64(output, &first, "total_vm", event->total_vm);
	json_u64(output, &first, "data_vm", event->data_vm);
	json_u64(output, &first, "exec_vm", event->exec_vm);
	json_u64(output, &first, "stack_vm", event->stack_vm);
	json_u64(output, &first, "pgtables_bytes", event->pgtables_bytes);
	json_i64(output, &first, "anon_pages", event->anon_pages);
	json_i64(output, &first, "file_pages", event->file_pages);
	json_i64(output, &first, "shmem_pages", event->shmem_pages);
	json_i64(output, &first, "swap_entries", event->swap_entries);
	json_u32(output, &first, "map_count", event->map_count);
	json_u32(output, &first, "vma_count", event->vma_count);
	json_comma(output, &first);
	fputs("\"vmas\":[", output);
	for (unsigned int i = 0; i < event->vma_count && i < MAX_VMAS; i++)
	{
		if (i)
			fputc(',', output);
		print_vma(output, &event->vmas[i]);
	}
	fputs("]}\n", output);
	fflush(output);
	return 0;
}

int main(void)
{
	/* These stay in function scope because every failure path shares one cleanup block. */
	struct mm_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	struct bpf_link *phase_link = NULL;
	FILE *output = NULL;
	int err = 0;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_options);

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	skel = mm_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "failed to open MM BPF skeleton\n");
		return 1;
	}
	unsigned long long page_offset_base = symbol_address("/proc/kallsyms", "page_offset_base");
	if (!page_offset_base)
	{
		fprintf(stderr, "failed to resolve x86 page-table layout symbols\n");
		err = 1;
		goto out;
	}
	skel->rodata->page_offset_base_address = page_offset_base;
	if (mm_bpf__load(skel) != 0)
	{
		fprintf(stderr, "failed to load MM BPF skeleton\n");
		err = 1;
		goto out;
	}
	unsigned long long phase_offset = elf_symbol_file_offset(WORKLOAD_PATH, "phase_boundary");
	if (!phase_offset)
	{
		fprintf(stderr, "failed to resolve phase_boundary symbol file offset in %s\n", WORKLOAD_PATH);
		err = 1;
		goto out;
	}
	fprintf(stderr, "attaching phase boundary uprobe at %s + 0x%llx\n", WORKLOAD_PATH, phase_offset);
	phase_link = bpf_program__attach_uprobe_opts(skel->progs.snapshot_phase_return, -1, WORKLOAD_PATH, phase_offset, &uprobe_options);
	if (!phase_link)
	{
		fprintf(stderr, "failed to attach phase boundary uprobe: %d\n", -errno);
		err = 1;
		goto out;
	}
	if (mkdir(CAPTURE_DIR, 0755) != 0 && errno != EEXIST)
	{
		perror("mkdir(" CAPTURE_DIR ")");
		err = 1;
		goto out;
	}
	output = fopen(CAPTURE_PATH, "a");
	if (!output)
	{
		perror("fopen(" CAPTURE_PATH ")");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, output, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "failed to create MM ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}

	fprintf(stderr, "capturing phase-boundary VMA snapshots to " CAPTURE_PATH "\n");
	while (!exiting)
	{
		err = ring_buffer__poll(ringbuf, 250);
		if (err == -EINTR)
			break;
		if (err < 0)
			goto out;
	}
	while (ring_buffer__consume(ringbuf) > 0)
		;
	err = 0;

out:
	ring_buffer__free(ringbuf);
	if (output)
		fclose(output);
	bpf_link__destroy(phase_link);
	mm_bpf__destroy(skel);
	return err ? 1 : 0;
}
