// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "ept.skel.h"

#define CAPTURE_DIR "captures"
#define CAPTURE_PATH CAPTURE_DIR "/ept.ndjson"
#define MAX_GFN_SAMPLES 32
#define EPT_LEVELS 4

/* Must match the BPF event byte-for-byte. */
struct ept_entry_record
{
	unsigned long long spte;
	unsigned long long table_hpa;
	unsigned short index;
	unsigned char level;
	unsigned char present;
	unsigned char mmio;
	unsigned char leaf;
	unsigned char readable;
	unsigned char writable;
	unsigned char executable;
};

struct guest_gfn
{
	unsigned long long gfn;
	unsigned long long gva;
	unsigned long long gpa;
	unsigned long long leaf_pfn;
	unsigned char ept_mapped;
	unsigned char ept_mmio;
	unsigned char leaf_level;
	struct ept_entry_record entries[EPT_LEVELS];
};

struct vcpu_mm_snapshot
{
	unsigned long long timestamp_ns;
	unsigned long long pid_tgid;
	unsigned long long trace_event;
	unsigned long long trace_reason;
	unsigned long long vcpu;
	unsigned long long kvm;
	unsigned long long mmu;
	unsigned long long root_hpa;
	unsigned long long root_pgd;
	unsigned long long rip;
	char comm[16];
	struct guest_gfn gfns[MAX_GFN_SAMPLES];
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

static void json_comma(FILE *output, int *first)
{
	if (*first)
	{
		*first = 0;
		return;
	}
	fputc(',', output);
}

static void json_string_value(FILE *output, const char *value, size_t limit)
{
	fputc('\"', output);
	for (size_t i = 0; i < limit && value[i]; i++)
	{
		unsigned char c = value[i];

		if (c == '\"' || c == '\\')
			fprintf(output, "\\%c", c);
		else if (c < 0x20)
			fprintf(output, "\\u%04x", c);
		else
			fputc(c, output);
	}
	fputc('\"', output);
}

static void json_string(FILE *output, int *first, const char *name, const char *value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":", name);
	json_string_value(output, value, 16);
}

static void json_literal_string(FILE *output, int *first, const char *name, const char *value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":", name);
	json_string_value(output, value, strlen(value));
}

static void json_u64(FILE *output, int *first, const char *name, unsigned long long value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":%llu", name, value);
}

static void json_hex(FILE *output, int *first, const char *name, unsigned long long value)
{
	json_comma(output, first);
	fprintf(output, "\"%s\":\"0x%llx\"", name, value);
}

static void print_entry(FILE *output, const struct ept_entry_record *entry)
{
	int first = 1;
	fputc('{', output);
	json_u64(output, &first, "level", entry->level);
	json_hex(output, &first, "table_hpa", entry->table_hpa);
	json_u64(output, &first, "index", entry->index);
	json_hex(output, &first, "spte", entry->spte);
	json_u64(output, &first, "present", entry->present);
	json_u64(output, &first, "mmio", entry->mmio);
	json_u64(output, &first, "leaf", entry->leaf);
	json_u64(output, &first, "r", entry->readable);
	json_u64(output, &first, "w", entry->writable);
	json_u64(output, &first, "x", entry->executable);
	fputc('}', output);
}

static const char *trace_event_name(unsigned long long event)
{
	if (event == 1)
		return "kvm_entry";
	if (event == 2)
		return "kvm_exit";
	if (event == 3)
		return "kvm_userspace_exit";
	return "unknown";
}

static void print_gfn(FILE *output, const struct guest_gfn *gfn)
{
	int first = 1;
	fputc('{', output);
	json_u64(output, &first, "gfn", gfn->gfn);
	json_hex(output, &first, "gva", gfn->gva);
	json_hex(output, &first, "gpa", gfn->gpa);
	json_u64(output, &first, "ept_mapped", gfn->ept_mapped);
	json_u64(output, &first, "ept_mmio", gfn->ept_mmio);
	json_u64(output, &first, "leaf_level", gfn->leaf_level);
	json_hex(output, &first, "leaf_pfn", gfn->leaf_pfn);
	json_comma(output, &first);
	fputs("\"entries\":[", output);
	for (int i = 0; i < EPT_LEVELS; i++)
	{
		if (i)
			fputc(',', output);
		print_entry(output, &gfn->entries[i]);
	}
	fputs("]}", output);
}

/* libbpf invokes this for every KVM tracepoint snapshot emitted by the BPF program. */
static int handle_event(void *context, void *data, size_t length)
{
	const struct vcpu_mm_snapshot *event = data;
	FILE *output = context;
	int first = 1;

	if (length < sizeof(*event))
		return 0;
	fputc('{', output);
	json_string(output, &first, "type", "vcpu_mm_snapshot");
	static unsigned int sequence;
	json_u64(output, &first, "sequence", sequence++);
	json_literal_string(output, &first, "trace_event", trace_event_name(event->trace_event));
	json_u64(output, &first, "trace_event_id", event->trace_event);
	json_u64(output, &first, "trace_reason", event->trace_reason);
	json_u64(output, &first, "timestamp_ns", event->timestamp_ns);
	json_string(output, &first, "comm", event->comm);
	json_hex(output, &first, "vcpu", event->vcpu);
	json_hex(output, &first, "kvm", event->kvm);
	json_hex(output, &first, "mmu", event->mmu);
	json_hex(output, &first, "root_hpa", event->root_hpa);
	json_hex(output, &first, "root_pgd", event->root_pgd);
	json_hex(output, &first, "rip", event->rip);
	json_comma(output, &first);
	fputs("\"gfns\":[", output);
	for (int i = 0; i < MAX_GFN_SAMPLES; i++)
	{
		if (i)
			fputc(',', output);
		print_gfn(output, &event->gfns[i]);
	}
	fputs("]}\n", output);
	fflush(output);
	return 0;
}

int main(void)
{
	/* These stay in function scope because every failure path shares one cleanup block. */
	struct ept_bpf *skel = NULL;
	struct ring_buffer *ringbuf = NULL;
	FILE *output = NULL;
	int err = 0;

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	skel = ept_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "failed to open EPT BPF skeleton\n");
		return 1;
	}
	unsigned long long page_offset_base = symbol_address("/proc/kallsyms", "page_offset_base");
	if (!page_offset_base)
	{
		fprintf(stderr, "failed to resolve page_offset_base\n");
		err = 1;
		goto out;
	}
	skel->rodata->page_offset_base_address = page_offset_base;
	if (ept_bpf__load(skel) != 0)
	{
		fprintf(stderr, "failed to load EPT BPF skeleton\n");
		err = 1;
		goto out;
	}
	if (ept_bpf__attach(skel) != 0)
	{
		fprintf(stderr, "failed to attach EPT BPF programs\n");
		err = 1;
		goto out;
	}
	if (mkdir(CAPTURE_DIR, 0755) != 0 && errno != EEXIST)
	{
		perror("mkdir(" CAPTURE_DIR ")");
		err = 1;
		goto out;
	}
	output = fopen(CAPTURE_PATH, "w");
	if (!output)
	{
		perror("fopen(" CAPTURE_PATH ")");
		err = 1;
		goto out;
	}
	ringbuf = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, output, NULL);
	if (!ringbuf)
	{
		fprintf(stderr, "failed to create EPT ring buffer: %d\n", -errno);
		err = 1;
		goto out;
	}
	fprintf(stderr, "capturing KVM EPT snapshots to " CAPTURE_PATH "\n");
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
	ept_bpf__destroy(skel);
	return err ? 1 : 0;
}
