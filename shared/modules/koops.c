// SPDX-License-Identifier: GPL-2.0
/* Combined task-topology and kernel-memory API study module. */

#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mmzone.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/fixmap.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/page_64_types.h>
#include <asm/pgtable.h>
#include <asm/pgtable_areas.h>
#include <asm/pgtable_64_types.h>
#include <asm/vsyscall.h>

#ifdef CONFIG_X86_64
#include <asm/cpu_entry_area.h>
#endif

static void show_idle_thread(void)
{
	struct task_struct *t = &init_task;

	/* init_task is CPU0's idle task and is not visited by normal traversal. */
	pr_info("KOOPS_EVT domain=core phase=tasks action=task tgid=%d pid=%d ppid=0 cpu=0 task=%px stack=%px mm=%px type=idle comm=\"%s\"\n",
			t->tgid, t->pid, t, t->stack, t->mm, t->comm);
}

static int show_all_threads(void)
{
	struct task_struct *p;
	struct task_struct *t;
	int total = 0;

	pr_info("KOOPS_EVT domain=core phase=tasks action=begin scope=all_threads\n");

	show_idle_thread();
	total++;

	rcu_read_lock();

	for_each_process_thread(p, t)
	{
		const char *type;
		int nr_threads;

		get_task_struct(t);
		task_lock(t);

		nr_threads = get_nr_threads(t);

		if (!t->mm)
			type = "kthread";
		else if (nr_threads > 1)
			type = "user-MT";
		else
			type = "user-ST";

		pr_info("KOOPS_EVT domain=core phase=tasks action=task tgid=%d pid=%d ppid=%d cpu=%d task=%px stack=%px mm=%px type=%s comm=\"%s\"\n",
				t->tgid,
				t->pid,
				task_ppid_nr(t),
				task_cpu(t),
				t,
				t->stack,
				t->mm,
				type,
				t->comm);

		task_unlock(t);
		put_task_struct(t);

		total++;
	}

	rcu_read_unlock();

	return total;
}

static int __init core_koops_init(void)
{
	int total;

	pr_info("KOOPS_EVT domain=core phase=lifecycle action=attached module=%s\n", KBUILD_MODNAME);
	total = show_all_threads();
	pr_info("KOOPS_EVT domain=core phase=tasks action=end total=%d\n", total);

	return 0;
}

static void __exit core_koops_exit(void)
{
	pr_info("KOOPS_EVT domain=core phase=lifecycle action=detached module=%s\n", KBUILD_MODNAME);
}

#ifndef CONFIG_X86_64
#error "This module is x86-64 only."
#endif

/* Use order-1 allocations where the page allocator should return 2 pages. */
#define BUDDY_PAGE_ORDER 1

/* Request a non-page-exact byte count for alloc_pages_exact(). */
#define EXACT_PAGE_ALLOC_SIZE (PAGE_SIZE + 100)

/* Request a small kmalloc() buffer so ksize() can show slab rounding. */
#define SLAB_BUFFER_SIZE 100

/* Custom slab cache settings for kmem_cache_create()/kmem_cache_alloc(). */
#define CUSTOM_CACHE_NAME "koops_mm_cache"
#define CUSTOM_CACHE_OBJECTS 8

/* Request multiple pages so vmalloc page mappings are easy to inspect. */
#define VMALLOC_BUFFER_SIZE (PAGE_SIZE + 100)

/* Page allocator results kept globally so module exit can free them. */
static unsigned long one_page;
static unsigned long zero_page;
static unsigned long order_pages;
static void *exact_pages;
static struct page *page_desc;
static void *page_desc_addr;

/* Small typed object used to show kzalloc() and kfree_sensitive(). */
struct slab_context
{
	char name[32];
	char secret[32];
	unsigned long created_at;
	unsigned int tx_count;
	unsigned int rx_count;
	u8 payload[64];
};

/* Object type served by the custom slab cache. */
struct custom_cache_object
{
	char name[32];
	unsigned long created_at;
	unsigned int id;
	unsigned int flags;
	u8 payload[64];
};

/* Slab allocator results kept globally so module exit can free them. */
static void *slab_buf;
static struct slab_context *ctx;
static struct kmem_cache *custom_cache;
static struct custom_cache_object *custom_objects[CUSTOM_CACHE_OBJECTS];

/* vmalloc allocator results kept globally so module exit can free them. */
static void *vbuf;
static void *vzbuf;

static int __init mm_koops_init(void);

/*
 * Kernel virtual address-space layout helpers
 * -------------------------------------------
 */

/* Print machine-readable kernel layout records. */
static void print_addr(const char *name, unsigned long addr)
{
	pr_info("KOOPS_EVT domain=mm phase=layout action=address id=%s addr=0x%016lx\n",
			name, addr);
}

static void print_region(const char *name, unsigned long start, unsigned long end,
			 const char *kind, const char *source)
{
	if (end <= start)
	{
		pr_warn("KOOPS_EVT domain=mm phase=layout action=region id=%s start=0x%016lx end=0x%016lx kind=%s source=%s valid=no\n",
				name, start, end, kind, source);
		return;
	}

	pr_info("KOOPS_EVT domain=mm phase=layout action=region id=%s start=0x%016lx end=0x%016lx bytes=%lu kind=%s source=%s valid=yes\n",
			name, start, end, end - start, kind, source);
}

static void __init print_global_constants(unsigned long ram_bytes)
{
	unsigned long canonical_end = (unsigned long)TASK_SIZE_MAX + PAGE_SIZE;
	unsigned long kernel_start = 0UL - canonical_end;
	unsigned long direct_map_end = (unsigned long)PAGE_OFFSET + ram_bytes;
	unsigned long vmemmap_bytes = (ram_bytes >> PAGE_SHIFT) * sizeof(struct page);
	unsigned long vmemmap_end = (unsigned long)VMEMMAP_START + vmemmap_bytes;
	unsigned long cpu_entry_area_end = (unsigned long)CPU_ENTRY_AREA_BASE +
					      CPU_ENTRY_AREA_MAP_SIZE;
	unsigned long espfix_end = (unsigned long)ESPFIX_BASE_ADDR + P4D_SIZE;
	unsigned int gap = 0;
	unsigned long cursor = 0;

#define PRINT_GAP_TO(next) \
	do { \
		unsigned long __next = (unsigned long)(next); \
		if (__next > cursor) { \
			char __name[32]; \
			snprintf(__name, sizeof(__name), "reserved_gap_%u", gap++); \
			print_region(__name, cursor, __next, "reserved", \
				     "adjacent_macro_boundaries"); \
		} \
		cursor = __next; \
	} while (0)

#define PRINT_ORDERED(name, start, end, kind, source) \
	do { \
		unsigned long __start = (unsigned long)(start); \
		unsigned long __end = (unsigned long)(end); \
		PRINT_GAP_TO(__start); \
		print_region((name), __start, __end, (kind), (source)); \
		if (__end > cursor) \
			cursor = __end; \
	} while (0)

	pr_info("KOOPS_EVT domain=mm phase=layout action=begin\n");
	pr_info("KOOPS_EVT domain=mm phase=layout action=constants page_size=%lu page_shift=%u page_mask=0x%016lx bits_per_long=%u ram_bytes=%lu paging_levels=%u\n",
			PAGE_SIZE, (unsigned int)PAGE_SHIFT, (unsigned long)PAGE_MASK,
			(unsigned int)BITS_PER_LONG, ram_bytes,
			pgtable_l5_enabled() ? 5U : 4U);

	print_addr("cpu_entry_area_base", (unsigned long)CPU_ENTRY_AREA_BASE);
	print_addr("mm_koops_init", (unsigned long)mm_koops_init);
	print_addr("vsyscall", (unsigned long)VSYSCALL_ADDR);

	PRINT_ORDERED("user_vas", 0UL, TASK_SIZE_MAX, "process_specific",
		      "TASK_SIZE_MAX");
	PRINT_ORDERED("user_guard", TASK_SIZE_MAX, canonical_end, "guard",
		      "TASK_SIZE_MAX+PAGE_SIZE");
	PRINT_ORDERED("noncanonical", canonical_end, kernel_start, "invalid",
		      "TASK_SIZE_MAX");
	PRINT_ORDERED("kernel_guard_hole", GUARD_HOLE_BASE_ADDR,
		      GUARD_HOLE_END_ADDR, "guard",
		      "GUARD_HOLE_BASE_ADDR+GUARD_HOLE_END_ADDR");
	PRINT_ORDERED("ldt_remap", LDT_BASE_ADDR, LDT_END_ADDR, "conditional",
		      "LDT_BASE_ADDR+LDT_END_ADDR");
	PRINT_ORDERED("direct_map_observed_ram", PAGE_OFFSET, direct_map_end,
		      "physical_direct_map", "PAGE_OFFSET+totalram_pages");
	PRINT_ORDERED("vmalloc", VMALLOC_START, VMALLOC_END, "vmalloc_ioremap",
		      "VMALLOC_START+VMALLOC_END");
	PRINT_ORDERED("vmemmap_observed_descriptors", VMEMMAP_START, vmemmap_end,
		      "struct_page_array",
		      "VMEMMAP_START+totalram_pages+sizeof_struct_page");
	PRINT_ORDERED("cpu_entry_area", CPU_ENTRY_AREA_BASE, cpu_entry_area_end,
		      "per_cpu_entry", "CPU_ENTRY_AREA_BASE+CPU_ENTRY_AREA_MAP_SIZE");
	PRINT_ORDERED("espfix", ESPFIX_BASE_ADDR, espfix_end, "espfix_stacks",
		      "ESPFIX_BASE_ADDR+P4D_SIZE");
	PRINT_ORDERED("efi_runtime", EFI_VA_END, EFI_VA_START, "efi_runtime",
		      "EFI_VA_END+EFI_VA_START");
	PRINT_ORDERED("kernel_image", __START_KERNEL_map,
		      (unsigned long)__START_KERNEL_map + KERNEL_IMAGE_SIZE,
		      "kernel_image", "__START_KERNEL_map+KERNEL_IMAGE_SIZE");
	PRINT_ORDERED("modules", MODULES_VADDR, MODULES_END, "module_space",
		      "MODULES_VADDR+MODULES_END");
	PRINT_ORDERED("fixmap", FIXADDR_START, FIXADDR_TOP, "fixed_mappings",
		      "FIXADDR_START+FIXADDR_TOP");
	if (cursor < ULONG_MAX)
		print_region("reserved_top", cursor, ULONG_MAX, "reserved",
			     "FIXADDR_TOP+ULONG_MAX");

	pr_info("KOOPS_EVT domain=mm phase=layout action=end\n");

#undef PRINT_ORDERED
#undef PRINT_GAP_TO
}

/*
 * Buddy/page allocator helpers
 * ----------------------------
 */

/* Convert a buddy allocator order into the number of bytes it covers. */
static size_t order_size_bytes(unsigned int page_order)
{
	return PAGE_SIZE << page_order;
}

/* Emit one compact sample instead of a multi-line hex dump. */
static void sample_memory(const char *name, const void *addr, size_t len)
{
	int sample_len = min_t(size_t, len, 16);

	pr_info("KOOPS_EVT domain=mm phase=memory action=sample id=%s bytes=%d data=%*phN\n",
			name, sample_len, sample_len, addr);
}

/* Show the virtual, physical, and PFN mapping for each page in an allocation. */
static void show_pages(const char *name, const void *addr, size_t len)
{
	unsigned int i;
	unsigned int pages;
	unsigned long kva;
	unsigned long previous_pfn = 0;
	bool physically_contiguous = true;

	if (!addr || !len)
		return;

	pages = DIV_ROUND_UP(len, PAGE_SIZE);
	kva = (unsigned long)addr;

	for (i = 0; i < pages; i++)
	{
		void *this_kva = (void *)(kva + i * PAGE_SIZE);
		phys_addr_t pa = virt_to_phys(this_kva);
		unsigned long pfn = PHYS_PFN(pa);

		pr_info("KOOPS_EVT domain=mm phase=mapping action=page id=%s index=%u kva=%px pa=%pa pfn=%lu\n",
				name, i, this_kva, &pa, pfn);

		if (i > 0 && pfn != previous_pfn + 1)
			physically_contiguous = false;

		previous_pfn = pfn;
	}

	pr_info("KOOPS_EVT domain=mm phase=mapping action=summary id=%s kva=%px bytes=%zu pages=%u virtual_contiguous=yes physical_contiguous=%s\n",
			name, addr, len, pages, physically_contiguous ? "yes" : "no");
}

/* Free every page allocation made by allocate_page_memory(). */
static void free_page_memory(void)
{
	if (exact_pages)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=free_pages_exact id=exact_pages addr=%px bytes=%lu\n",
				exact_pages, (unsigned long)EXACT_PAGE_ALLOC_SIZE);
		free_pages_exact(exact_pages, EXACT_PAGE_ALLOC_SIZE);
		exact_pages = NULL;
	}

	if (page_desc)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=__free_pages id=page_desc addr=%px order=%u\n",
				page_desc_addr, BUDDY_PAGE_ORDER);
		__free_pages(page_desc, BUDDY_PAGE_ORDER);
		page_desc = NULL;
		page_desc_addr = NULL;
	}

	if (order_pages)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=free_pages id=order_pages addr=%px order=%u\n",
				(void *)order_pages, BUDDY_PAGE_ORDER);
		free_pages(order_pages, BUDDY_PAGE_ORDER);
		order_pages = 0;
	}

	if (zero_page)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=free_page id=zero_page addr=%px order=0\n",
				(void *)zero_page);
		free_page(zero_page);
		zero_page = 0;
	}

	if (one_page)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=free_page id=one_page addr=%px order=0\n",
				(void *)one_page);
		free_page(one_page);
		one_page = 0;
	}
}

/* Exercise common page allocator APIs and print what each one returned. */
static int allocate_page_memory(void)
{
	size_t order_len = order_size_bytes(BUDDY_PAGE_ORDER);

	if (BUDDY_PAGE_ORDER > MAX_PAGE_ORDER - 1)
	{
		pr_err("KOOPS_EVT domain=mm phase=page_allocator action=error api=order_validation order=%u max_order=%u errno=%d\n",
			   BUDDY_PAGE_ORDER, MAX_PAGE_ORDER - 1, -EINVAL);
		return -EINVAL;
	}

	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=begin\n");

	one_page = __get_free_page(GFP_KERNEL);
	if (!one_page)
		return -ENOMEM;

	memset((void *)one_page, 0x11, PAGE_SIZE);
	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=alloc api=__get_free_page id=one_page addr=%px bytes=%lu order=0 zeroed=no\n",
			(void *)one_page, PAGE_SIZE);
	show_pages("one_page", (void *)one_page, PAGE_SIZE);
	sample_memory("one_page", (void *)one_page, PAGE_SIZE);

	zero_page = get_zeroed_page(GFP_KERNEL);
	if (!zero_page)
		goto err_nomem;

	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=alloc api=get_zeroed_page id=zero_page addr=%px bytes=%lu order=0 zeroed=yes\n",
			(void *)zero_page, PAGE_SIZE);
	show_pages("zero_page", (void *)zero_page, PAGE_SIZE);
	sample_memory("zero_page", (void *)zero_page, PAGE_SIZE);

	order_pages = __get_free_pages(GFP_KERNEL | __GFP_ZERO, BUDDY_PAGE_ORDER);
	if (!order_pages)
		goto err_nomem;

	memset((void *)order_pages, 0x22, order_len);
	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=alloc api=__get_free_pages id=order_pages order=%u pages=%u addr=%px bytes=%zu zeroed=requested\n",
			BUDDY_PAGE_ORDER, 1U << BUDDY_PAGE_ORDER, (void *)order_pages, order_len);
	show_pages("order_pages", (void *)order_pages, order_len);
	sample_memory("order_pages", (void *)order_pages, order_len);

	page_desc = alloc_pages(GFP_KERNEL | __GFP_ZERO, BUDDY_PAGE_ORDER);
	if (!page_desc)
		goto err_nomem;

	page_desc_addr = page_address(page_desc);
	if (!page_desc_addr)
	{
		pr_err("KOOPS_EVT domain=mm phase=page_allocator action=error api=page_address id=page_desc reason=no_direct_mapping errno=%d\n",
			   -ENOMEM);
		free_page_memory();
		return -ENOMEM;
	}

	memset(page_desc_addr, 0x33, order_len);
	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=alloc api=alloc_pages id=page_desc order=%u struct_page=%px addr=%px bytes=%zu zeroed=requested\n",
			BUDDY_PAGE_ORDER, page_desc, page_desc_addr, order_len);
	show_pages("page_desc", page_desc_addr, order_len);
	sample_memory("page_desc", page_desc_addr, order_len);

	exact_pages = alloc_pages_exact(EXACT_PAGE_ALLOC_SIZE, GFP_KERNEL | __GFP_ZERO);
	if (!exact_pages)
		goto err_nomem;

	memset(exact_pages, 0x44, EXACT_PAGE_ALLOC_SIZE);
	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=alloc api=alloc_pages_exact id=exact_pages requested=%lu addr=%px pages=%u\n",
			(unsigned long)EXACT_PAGE_ALLOC_SIZE, exact_pages,
			(unsigned int)DIV_ROUND_UP(EXACT_PAGE_ALLOC_SIZE, PAGE_SIZE));
	show_pages("exact_pages", exact_pages, EXACT_PAGE_ALLOC_SIZE);
	sample_memory("exact_pages", exact_pages, EXACT_PAGE_ALLOC_SIZE);
	pr_info("KOOPS_EVT domain=mm phase=page_allocator action=end allocations=5\n");

	return 0;

err_nomem:
	free_page_memory();
	return -ENOMEM;
}

/*
 * Slab allocator helpers
 * ----------------------
 */

/* Free every slab allocation made by allocate_slab_memory(). */
static void free_slab_memory(void)
{
	if (ctx)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=kfree_sensitive id=slab_context addr=%px\n", ctx);
		kfree_sensitive(ctx);
		ctx = NULL;
	}

	if (slab_buf)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=kfree id=slab_buf addr=%px\n", slab_buf);
		kfree(slab_buf);
		slab_buf = NULL;
	}
}

/* Exercise common slab allocator APIs and print what each one returned. */
static int allocate_slab_memory(void)
{
	size_t actual;

	pr_info("KOOPS_EVT domain=mm phase=slab action=begin\n");

	slab_buf = kmalloc(SLAB_BUFFER_SIZE, GFP_KERNEL);
	if (!slab_buf)
		return -ENOMEM;

	memset(slab_buf, 'K', SLAB_BUFFER_SIZE);
	actual = ksize(slab_buf);

	pr_info("KOOPS_EVT domain=mm phase=slab action=alloc api=kmalloc id=slab_buf requested=%u actual=%zu waste=%zu addr=%px zeroed=no\n",
			SLAB_BUFFER_SIZE,
			actual,
			actual >= SLAB_BUFFER_SIZE ? actual - SLAB_BUFFER_SIZE : 0,
			slab_buf);
	show_pages("slab_buf", slab_buf, actual);
	sample_memory("slab_buf", slab_buf, SLAB_BUFFER_SIZE);

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		goto err_nomem;

	ctx->tx_count = 100;
	ctx->rx_count = 200;
	ctx->created_at = jiffies;
	strscpy(ctx->name, "mm-study-context", sizeof(ctx->name));
	strscpy(ctx->secret, "erase-this-secret", sizeof(ctx->secret));
	memset(ctx->payload, 0x5a, sizeof(ctx->payload));

	actual = ksize(ctx);

	pr_info("KOOPS_EVT domain=mm phase=slab action=alloc api=kzalloc id=slab_context requested=%zu actual=%zu waste=%zu addr=%px zeroed=yes\n",
			sizeof(*ctx),
			actual,
			actual >= sizeof(*ctx) ? actual - sizeof(*ctx) : 0,
			ctx);
	show_pages("slab_context", ctx, actual);
	sample_memory("slab_context", ctx, sizeof(*ctx));
	pr_info("KOOPS_EVT domain=mm phase=slab action=end allocations=2\n");

	return 0;

err_nomem:
	free_slab_memory();
	return -ENOMEM;
}

/*
 * Custom slab cache helpers
 * -------------------------
 */

/* Initialize each object when the custom cache grows. */
static void custom_cache_ctor(void *addr)
{
	struct custom_cache_object *obj = addr;

	obj->flags = 0xcafe;
	strscpy(obj->name, "constructed", sizeof(obj->name));
	memset(obj->payload, 0xcc, sizeof(obj->payload));
}

/* Free custom slab cache objects and destroy the cache. */
static void free_custom_slab_cache(void)
{
	unsigned int i;

	for (i = 0; i < CUSTOM_CACHE_OBJECTS; i++)
	{
		if (custom_objects[i])
		{
			pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=kmem_cache_free id=custom_object_%u addr=%px cache=%s\n",
					i, custom_objects[i], CUSTOM_CACHE_NAME);
			kmem_cache_free(custom_cache, custom_objects[i]);
			custom_objects[i] = NULL;
		}
	}

	if (custom_cache)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=destroy api=kmem_cache_destroy id=custom_cache name=%s\n",
				CUSTOM_CACHE_NAME);
		kmem_cache_destroy(custom_cache);
		custom_cache = NULL;
	}
}

/* Exercise kmem_cache_create() and kmem_cache_alloc() with a typed object. */
static int create_custom_slab_cache(void)
{
	unsigned int i;

	pr_info("KOOPS_EVT domain=mm phase=custom_cache action=begin\n");

	custom_cache = kmem_cache_create(CUSTOM_CACHE_NAME,
									 sizeof(struct custom_cache_object),
									 0,
									 SLAB_HWCACHE_ALIGN,
									 custom_cache_ctor);
	if (!custom_cache)
	{
		pr_warn("KOOPS_EVT domain=mm phase=custom_cache action=error api=kmem_cache_create errno=%d\n", -ENOMEM);
		return -ENOMEM;
	}

	pr_info("KOOPS_EVT domain=mm phase=custom_cache action=create api=kmem_cache_create id=custom_cache name=%s object_size=%zu objects=%u\n",
			CUSTOM_CACHE_NAME, sizeof(struct custom_cache_object), CUSTOM_CACHE_OBJECTS);

	for (i = 0; i < CUSTOM_CACHE_OBJECTS; i++)
	{
		custom_objects[i] = kmem_cache_alloc(custom_cache, GFP_KERNEL);
		if (!custom_objects[i])
		{
			pr_warn("KOOPS_EVT domain=mm phase=custom_cache action=error api=kmem_cache_alloc index=%u errno=%d\n", i, -ENOMEM);
			free_custom_slab_cache();
			return -ENOMEM;
		}

		custom_objects[i]->id = i;
		custom_objects[i]->created_at = jiffies;
		strscpy(custom_objects[i]->name, "active-object",
				sizeof(custom_objects[i]->name));
		memset(custom_objects[i]->payload, 0xa0 + i,
			   sizeof(custom_objects[i]->payload));

		pr_info("KOOPS_EVT domain=mm phase=custom_cache action=alloc api=kmem_cache_alloc id=custom_object_%u addr=%px object_id=%u flags=0x%x name=%s\n",
				i,
				custom_objects[i],
				custom_objects[i]->id,
				custom_objects[i]->flags,
				custom_objects[i]->name);
	}

	show_pages("custom_object_0", custom_objects[0], sizeof(*custom_objects[0]));
	sample_memory("custom_object_0", custom_objects[0],
				  sizeof(*custom_objects[0]));
	pr_info("KOOPS_EVT domain=mm phase=custom_cache action=end objects=%u\n",
			CUSTOM_CACHE_OBJECTS);

	return 0;
}

/*
 * vmalloc allocator helpers
 * -------------------------
 */

/* Show which physical pages back a virtually contiguous vmalloc allocation. */
static void show_vmalloc_mapping(const char *name, const void *addr, size_t len)
{
	unsigned int i;
	unsigned int pages;
	unsigned long kva;
	unsigned long previous_pfn = 0;
	bool physically_contiguous = true;

	if (!addr || !len)
		return;

	pages = DIV_ROUND_UP(len, PAGE_SIZE);
	kva = (unsigned long)addr;

	for (i = 0; i < pages; i++)
	{
		void *this_kva = (void *)(kva + i * PAGE_SIZE);
		struct page *page = vmalloc_to_page(this_kva);
		phys_addr_t pa;
		unsigned long pfn;

		if (!page)
		{
			pr_warn("KOOPS_EVT domain=mm phase=mapping action=missing_page id=%s index=%u kva=%px\n",
					name, i, this_kva);
			continue;
		}

		pfn = page_to_pfn(page);
		pa = page_to_phys(page) + offset_in_page(this_kva);

		pr_info("KOOPS_EVT domain=mm phase=mapping action=page id=%s index=%u kva=%px struct_page=%px pa=%pa pfn=%lu\n",
				name, i, this_kva, page, &pa, pfn);

		if (i > 0 && pfn != previous_pfn + 1)
			physically_contiguous = false;

		previous_pfn = pfn;
	}

	pr_info("KOOPS_EVT domain=mm phase=mapping action=summary id=%s kva=%px bytes=%zu pages=%u virtual_contiguous=yes physical_contiguous=%s\n",
			name, addr, len, pages, physically_contiguous ? "yes" : "no");
}

/* Free every vmalloc allocation made by allocate_vmalloc_memory(). */
static void free_vmalloc_memory(void)
{
	if (vzbuf)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=vfree id=vzbuf addr=%px\n", vzbuf);
		vfree(vzbuf);
		vzbuf = NULL;
	}

	if (vbuf)
	{
		pr_info("KOOPS_EVT domain=mm phase=cleanup action=free api=vfree id=vbuf addr=%px\n", vbuf);
		vfree(vbuf);
		vbuf = NULL;
	}
}

/* Exercise vmalloc() and vzalloc() without mixing them with page/slab APIs. */
static int allocate_vmalloc_memory(void)
{
	pr_info("KOOPS_EVT domain=mm phase=vmalloc action=begin\n");

	vbuf = vmalloc(VMALLOC_BUFFER_SIZE);
	if (!vbuf)
	{
		pr_warn("KOOPS_EVT domain=mm phase=vmalloc action=error api=vmalloc requested=%lu errno=%d\n",
				(unsigned long)VMALLOC_BUFFER_SIZE, -ENOMEM);
		return -ENOMEM;
	}

	memset(vbuf, 0x5a, VMALLOC_BUFFER_SIZE);
	pr_info("KOOPS_EVT domain=mm phase=vmalloc action=alloc api=vmalloc id=vbuf requested=%lu addr=%px zeroed=no\n",
			(unsigned long)VMALLOC_BUFFER_SIZE, vbuf);
	sample_memory("vbuf", vbuf, VMALLOC_BUFFER_SIZE);
	show_vmalloc_mapping("vbuf", vbuf, VMALLOC_BUFFER_SIZE);

	vzbuf = vzalloc(VMALLOC_BUFFER_SIZE);
	if (!vzbuf)
	{
		pr_warn("KOOPS_EVT domain=mm phase=vmalloc action=error api=vzalloc requested=%lu errno=%d\n",
				(unsigned long)VMALLOC_BUFFER_SIZE, -ENOMEM);
		free_vmalloc_memory();
		return -ENOMEM;
	}

	pr_info("KOOPS_EVT domain=mm phase=vmalloc action=alloc api=vzalloc id=vzbuf requested=%lu addr=%px zeroed=yes\n",
			(unsigned long)VMALLOC_BUFFER_SIZE, vzbuf);
	sample_memory("vzbuf", vzbuf, VMALLOC_BUFFER_SIZE);
	show_vmalloc_mapping("vzbuf", vzbuf, VMALLOC_BUFFER_SIZE);
	pr_info("KOOPS_EVT domain=mm phase=vmalloc action=end allocations=2\n");

	return 0;
}

/*
 * Module lifecycle
 * ----------------
 */

/* Module entry point: print layout information, then run allocator studies. */
static int __init mm_koops_init(void)
{
	int ret;
	unsigned long ram_bytes = totalram_pages() << PAGE_SHIFT;

	pr_info("KOOPS_EVT domain=mm phase=lifecycle action=attached current_pid=%d current_cpu=%d current_comm=\"%s\"\n",
			current->pid, task_cpu(current), current->comm);

	print_global_constants(ram_bytes);

	ret = allocate_page_memory();
	if (ret)
		return ret;

	ret = allocate_slab_memory();
	if (ret)
	{
		free_page_memory();
		return ret;
	}

	ret = create_custom_slab_cache();
	if (ret)
	{
		free_slab_memory();
		free_page_memory();
		return ret;
	}

	ret = allocate_vmalloc_memory();
	if (ret)
	{
		free_custom_slab_cache();
		free_slab_memory();
		free_page_memory();
		return ret;
	}

	return 0;
}

/* Module exit point: release allocations and report unload. */
static void __exit mm_koops_exit(void)
{
	pr_info("KOOPS_EVT domain=mm phase=cleanup action=begin\n");
	print_addr("mm_koops_exit", (unsigned long)mm_koops_exit);
	free_vmalloc_memory();
	free_custom_slab_cache();
	free_slab_memory();
	free_page_memory();
	pr_info("KOOPS_EVT domain=mm phase=cleanup action=end\n");
	pr_info("KOOPS_EVT domain=mm phase=lifecycle action=detached\n");
}

static int __init koops_init(void)
{
	int ret;

	pr_info("KOOPS_EVT domain=module phase=lifecycle action=run_begin schema=1 module=%s\n", KBUILD_MODNAME);

	ret = core_koops_init();
	if (ret)
	{
		pr_err("KOOPS_EVT domain=module phase=lifecycle action=run_end status=error stage=core errno=%d\n", ret);
		return ret;
	}

	ret = mm_koops_init();
	if (ret)
	{
		core_koops_exit();
		pr_err("KOOPS_EVT domain=module phase=lifecycle action=run_end status=error stage=mm errno=%d\n", ret);
		return ret;
	}

	pr_info("KOOPS_EVT domain=module phase=lifecycle action=ready status=ok\n");
	return 0;
}

static void __exit koops_exit(void)
{
	mm_koops_exit();
	core_koops_exit();
	pr_info("KOOPS_EVT domain=module phase=lifecycle action=run_end status=ok\n");
}

module_init(koops_init);
module_exit(koops_exit);
MODULE_AUTHOR("Manoj Khatri");
MODULE_DESCRIPTION("Combined task and memory-management study module");
MODULE_LICENSE("GPL");
