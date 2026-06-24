// SPDX-License-Identifier: GPL-2.0
/*
 * mm_koops.c
 *
 * Small x86-64 kernel virtual address-space layout study module.
 * Prints layout macros, named regions, and allocator behavior.
 */

#include <linux/gfp.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>

#include <asm/fixmap.h>
#include <asm/io.h>
#include <asm/page.h>
#include <asm/page_64_types.h>
#include <asm/pgtable.h>
#include <asm/pgtable_64_types.h>

#ifdef CONFIG_X86_64
#include <asm/cpu_entry_area.h>
#endif

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
struct slab_context {
	char name[32];
	char secret[32];
	unsigned long created_at;
	unsigned int tx_count;
	unsigned int rx_count;
	u8 payload[64];
};

/* Object type served by the custom slab cache. */
struct custom_cache_object {
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

/* Print one named kernel virtual address in a consistent format. */
static void print_addr(const char *name, unsigned long addr)
{
	pr_info("KOOPS_MM %-24s = 0x%016lx\n", name, addr);
}

/* Print one named virtual address range and its size. */
static void print_region(const char *name, unsigned long start, unsigned long end)
{
	unsigned long size_kib;

	if (end <= start) {
		pr_info("KOOPS_MM %-24s 0x%016lx - 0x%016lx  invalid\n",
			name, start, end);
		return;
	}

	size_kib = (end - start) >> 10;

	pr_info("KOOPS_MM %-24s 0x%016lx - 0x%016lx  %lu KiB\n",
		name, start, end, size_kib);
}

/* Print global memory constants and the kernel virtual address-space layout. */
static void print_global_constants(unsigned long ram_bytes)
{
	pr_info("KOOPS_MM ---- memory constants ----\n");
	pr_info("KOOPS_MM PAGE_SIZE           : %lu bytes\n", PAGE_SIZE);
	pr_info("KOOPS_MM PAGE_SHIFT          : %u\n", (unsigned int)PAGE_SHIFT);
	pr_info("KOOPS_MM PAGE_MASK           : 0x%016lx\n", (unsigned long)PAGE_MASK);
	pr_info("KOOPS_MM BITS_PER_LONG       : %u\n", (unsigned int)BITS_PER_LONG);
	pr_info("KOOPS_MM approx RAM          : %lu MiB\n", ram_bytes >> 20);
	pr_info("KOOPS_MM paging mode         : %s\n",
		pgtable_l5_enabled() ? "5-level paging / LA57" : "4-level paging");

	pr_info("KOOPS_MM ---- kernel VAS layout ----\n");
	print_addr("CPU_ENTRY_AREA_BASE", (unsigned long)CPU_ENTRY_AREA_BASE);
	print_addr("mm_koops_init", (unsigned long)mm_koops_init);

	print_region("user VAS", 0UL, (unsigned long)TASK_SIZE);
	print_region("direct map approx",
		     (unsigned long)PAGE_OFFSET,
		     (unsigned long)PAGE_OFFSET + ram_bytes);
	print_region("vmalloc", (unsigned long)VMALLOC_START, (unsigned long)VMALLOC_END);
	print_region("modules", (unsigned long)MODULES_VADDR, (unsigned long)MODULES_END);
	print_region("fixmap", (unsigned long)FIXADDR_START, (unsigned long)FIXADDR_TOP);

#ifdef KERNEL_IMAGE_SIZE
	print_region("kernel image max",
		     (unsigned long)__START_KERNEL_map,
		     (unsigned long)__START_KERNEL_map + KERNEL_IMAGE_SIZE);
#endif
#if defined(VMEMMAP_START) && defined(VMEMMAP_END)
	print_region("vmemmap", (unsigned long)VMEMMAP_START, (unsigned long)VMEMMAP_END);
#endif
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

/* Dump a small prefix of an allocation so fill patterns are visible in dmesg. */
static void dump_memory(const char *prefix, const void *addr, size_t len)
{
	print_hex_dump(KERN_INFO, prefix, DUMP_PREFIX_OFFSET, 16, 1,
		       addr, min_t(size_t, len, 64), false);
}

/* Show the virtual, physical, and PFN mapping for each page in an allocation. */
static void show_pages(const char *name, const void *addr, size_t len)
{
	unsigned int i;
	unsigned int pages;
	unsigned long kva;
	unsigned long previous_pfn = 0;

	if (!addr || !len)
		return;

	pages = DIV_ROUND_UP(len, PAGE_SIZE);
	kva = (unsigned long)addr;

	pr_info("KOOPS_MM %s: kva=%px len=%zu pages=%u\n", name, addr, len, pages);

	for (i = 0; i < pages; i++) {
		void *this_kva = (void *)(kva + i * PAGE_SIZE);
		phys_addr_t pa = virt_to_phys(this_kva);
		unsigned long pfn = PHYS_PFN(pa);

		pr_info("KOOPS_MM %s[%u]: kva=%px pa=%pa pfn=%lu\n",
			name, i, this_kva, &pa, pfn);

		if (i > 0 && pfn != previous_pfn + 1) {
			pr_warn("KOOPS_MM %s: PFNs are not contiguous at page %u\n",
				name, i);
		}

		previous_pfn = pfn;
	}
}

/* Free every page allocation made by allocate_page_memory(). */
static void free_page_memory(void)
{
	if (exact_pages) {
		free_pages_exact(exact_pages, EXACT_PAGE_ALLOC_SIZE);
		exact_pages = NULL;
	}

	if (page_desc) {
		__free_pages(page_desc, BUDDY_PAGE_ORDER);
		page_desc = NULL;
		page_desc_addr = NULL;
	}

	if (order_pages) {
		free_pages(order_pages, BUDDY_PAGE_ORDER);
		order_pages = 0;
	}

	if (zero_page) {
		free_page(zero_page);
		zero_page = 0;
	}

	if (one_page) {
		free_page(one_page);
		one_page = 0;
	}
}

/* Exercise common page allocator APIs and print what each one returned. */
static int allocate_page_memory(void)
{
	size_t order_len = order_size_bytes(BUDDY_PAGE_ORDER);

	if (BUDDY_PAGE_ORDER > MAX_ORDER - 1) {
		pr_err("KOOPS_MM order=%u is too large; max usable order is %u\n",
		       BUDDY_PAGE_ORDER, MAX_ORDER - 1);
		return -EINVAL;
	}

	pr_info("KOOPS_MM ---- page allocator ----\n");

	one_page = __get_free_page(GFP_KERNEL);
	if (!one_page)
		return -ENOMEM;

	memset((void *)one_page, 0x11, PAGE_SIZE);
	pr_info("KOOPS_MM __get_free_page(): addr=%px size=%lu\n",
		(void *)one_page, PAGE_SIZE);
	show_pages("__get_free_page", (void *)one_page, PAGE_SIZE);
	dump_memory("KOOPS_MM __get_free_page dump: ", (void *)one_page, PAGE_SIZE);

	zero_page = get_zeroed_page(GFP_KERNEL);
	if (!zero_page)
		goto err_nomem;

	pr_info("KOOPS_MM get_zeroed_page(): addr=%px size=%lu\n",
		(void *)zero_page, PAGE_SIZE);
	show_pages("get_zeroed_page", (void *)zero_page, PAGE_SIZE);
	dump_memory("KOOPS_MM get_zeroed_page dump: ", (void *)zero_page, PAGE_SIZE);

	order_pages = __get_free_pages(GFP_KERNEL | __GFP_ZERO, BUDDY_PAGE_ORDER);
	if (!order_pages)
		goto err_nomem;

	memset((void *)order_pages, 0x22, order_len);
	pr_info("KOOPS_MM __get_free_pages(): order=%u pages=%u addr=%px size=%zu\n",
		BUDDY_PAGE_ORDER, 1U << BUDDY_PAGE_ORDER, (void *)order_pages, order_len);
	show_pages("__get_free_pages", (void *)order_pages, order_len);
	dump_memory("KOOPS_MM __get_free_pages dump: ", (void *)order_pages, order_len);

	page_desc = alloc_pages(GFP_KERNEL | __GFP_ZERO, BUDDY_PAGE_ORDER);
	if (!page_desc)
		goto err_nomem;

	page_desc_addr = page_address(page_desc);
	if (!page_desc_addr) {
		pr_err("KOOPS_MM alloc_pages(): page has no direct kernel mapping\n");
		free_page_memory();
		return -ENOMEM;
	}

	memset(page_desc_addr, 0x33, order_len);
	pr_info("KOOPS_MM alloc_pages(): order=%u struct_page=%px addr=%px size=%zu\n",
		BUDDY_PAGE_ORDER, page_desc, page_desc_addr, order_len);
	show_pages("alloc_pages", page_desc_addr, order_len);
	dump_memory("KOOPS_MM alloc_pages dump: ", page_desc_addr, order_len);

	exact_pages = alloc_pages_exact(EXACT_PAGE_ALLOC_SIZE, GFP_KERNEL | __GFP_ZERO);
	if (!exact_pages)
		goto err_nomem;

	memset(exact_pages, 0x44, EXACT_PAGE_ALLOC_SIZE);
	pr_info("KOOPS_MM alloc_pages_exact(): requested=%lu addr=%px\n",
		(unsigned long)EXACT_PAGE_ALLOC_SIZE, exact_pages);
	show_pages("alloc_pages_exact", exact_pages, EXACT_PAGE_ALLOC_SIZE);
	dump_memory("KOOPS_MM alloc_pages_exact dump: ", exact_pages, EXACT_PAGE_ALLOC_SIZE);

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
	if (ctx) {
		kfree_sensitive(ctx);
		ctx = NULL;
	}

	if (slab_buf) {
		kfree(slab_buf);
		slab_buf = NULL;
	}
}

/* Exercise common slab allocator APIs and print what each one returned. */
static int allocate_slab_memory(void)
{
	size_t actual;

	pr_info("KOOPS_MM ---- slab allocator ----\n");

	slab_buf = kmalloc(SLAB_BUFFER_SIZE, GFP_KERNEL);
	if (!slab_buf)
		return -ENOMEM;

	memset(slab_buf, 'K', SLAB_BUFFER_SIZE);
	actual = ksize(slab_buf);

	pr_info("KOOPS_MM kmalloc(): requested=%u actual=%zu waste=%zu addr=%px\n",
		SLAB_BUFFER_SIZE,
		actual,
		actual >= SLAB_BUFFER_SIZE ? actual - SLAB_BUFFER_SIZE : 0,
		slab_buf);
	show_pages("kmalloc", slab_buf, actual);
	dump_memory("KOOPS_MM kmalloc dump: ", slab_buf, SLAB_BUFFER_SIZE);

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

	pr_info("KOOPS_MM kzalloc(ctx): requested=%zu actual=%zu waste=%zu addr=%px\n",
		sizeof(*ctx),
		actual,
		actual >= sizeof(*ctx) ? actual - sizeof(*ctx) : 0,
		ctx);
	show_pages("kzalloc_ctx", ctx, actual);
	dump_memory("KOOPS_MM kzalloc ctx dump: ", ctx, sizeof(*ctx));

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

	for (i = 0; i < CUSTOM_CACHE_OBJECTS; i++) {
		if (custom_objects[i]) {
			kmem_cache_free(custom_cache, custom_objects[i]);
			custom_objects[i] = NULL;
		}
	}

	if (custom_cache) {
		kmem_cache_destroy(custom_cache);
		custom_cache = NULL;
	}
}

/* Exercise kmem_cache_create() and kmem_cache_alloc() with a typed object. */
static int create_custom_slab_cache(void)
{
	unsigned int i;

	pr_info("KOOPS_MM ---- custom slab allocator ----\n");

	custom_cache = kmem_cache_create(CUSTOM_CACHE_NAME,
					       sizeof(struct custom_cache_object),
					       0,
					       SLAB_HWCACHE_ALIGN,
					       custom_cache_ctor);
	if (!custom_cache) {
		pr_warn("KOOPS_MM kmem_cache_create() failed\n");
		return -ENOMEM;
	}

	pr_info("KOOPS_MM kmem_cache_create(): name=%s object_size=%zu\n",
		CUSTOM_CACHE_NAME, sizeof(struct custom_cache_object));

	for (i = 0; i < CUSTOM_CACHE_OBJECTS; i++) {
		custom_objects[i] = kmem_cache_alloc(custom_cache, GFP_KERNEL);
		if (!custom_objects[i]) {
			pr_warn("KOOPS_MM kmem_cache_alloc() failed at object %u\n", i);
			free_custom_slab_cache();
			return -ENOMEM;
		}

		custom_objects[i]->id = i;
		custom_objects[i]->created_at = jiffies;
		strscpy(custom_objects[i]->name, "active-object",
			sizeof(custom_objects[i]->name));
		memset(custom_objects[i]->payload, 0xa0 + i,
		       sizeof(custom_objects[i]->payload));

		pr_info("KOOPS_MM kmem_cache_alloc(): object[%u]=%px id=%u flags=0x%x name=%s\n",
			i,
			custom_objects[i],
			custom_objects[i]->id,
			custom_objects[i]->flags,
			custom_objects[i]->name);
	}

	show_pages("custom_slab_object", custom_objects[0], sizeof(*custom_objects[0]));
	dump_memory("KOOPS_MM custom slab object[0] dump: ",
		    custom_objects[0],
		    sizeof(*custom_objects[0]));

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

	if (!addr || !len)
		return;

	pages = DIV_ROUND_UP(len, PAGE_SIZE);
	kva = (unsigned long)addr;

	pr_info("KOOPS_MM %s: kva=%px len=%zu pages=%u vmalloc=%s\n",
		name, addr, len, pages, is_vmalloc_addr(addr) ? "yes" : "no");

	for (i = 0; i < pages; i++) {
		void *this_kva = (void *)(kva + i * PAGE_SIZE);
		struct page *page = vmalloc_to_page(this_kva);
		phys_addr_t pa;
		unsigned long pfn;

		if (!page) {
			pr_warn("KOOPS_MM %s[%u]: kva=%px has no backing page\n",
				name, i, this_kva);
			continue;
		}

		pfn = page_to_pfn(page);
		pa = page_to_phys(page) + offset_in_page(this_kva);

		pr_info("KOOPS_MM %s[%u]: kva=%px page=%px pa=%pa pfn=%lu\n",
			name, i, this_kva, page, &pa, pfn);

		if (i > 0 && pfn != previous_pfn + 1) {
			pr_warn("KOOPS_MM %s: PFNs are not contiguous at page %u\n",
				name, i);
		}

		previous_pfn = pfn;
	}
}

/* Free every vmalloc allocation made by allocate_vmalloc_memory(). */
static void free_vmalloc_memory(void)
{
	if (vzbuf) {
		vfree(vzbuf);
		vzbuf = NULL;
	}

	if (vbuf) {
		vfree(vbuf);
		vbuf = NULL;
	}
}

/* Exercise vmalloc() and vzalloc() without mixing them with page/slab APIs. */
static int allocate_vmalloc_memory(void)
{
	pr_info("KOOPS_MM ---- vmalloc allocator ----\n");

	vbuf = vmalloc(VMALLOC_BUFFER_SIZE);
	if (!vbuf) {
		pr_warn("KOOPS_MM vmalloc(%lu) failed\n", (unsigned long)VMALLOC_BUFFER_SIZE);
		return -ENOMEM;
	}

	memset(vbuf, 0x5a, VMALLOC_BUFFER_SIZE);
	pr_info("KOOPS_MM vmalloc(): requested=%lu returned=%px\n",
		(unsigned long)VMALLOC_BUFFER_SIZE, vbuf);
	dump_memory("KOOPS_MM vmalloc buffer: ", vbuf, VMALLOC_BUFFER_SIZE);
	show_vmalloc_mapping("vmalloc", vbuf, VMALLOC_BUFFER_SIZE);

	vzbuf = vzalloc(VMALLOC_BUFFER_SIZE);
	if (!vzbuf) {
		pr_warn("KOOPS_MM vzalloc(%lu) failed\n", (unsigned long)VMALLOC_BUFFER_SIZE);
		free_vmalloc_memory();
		return -ENOMEM;
	}

	pr_info("KOOPS_MM vzalloc(): requested=%lu returned=%px\n",
		(unsigned long)VMALLOC_BUFFER_SIZE, vzbuf);
	dump_memory("KOOPS_MM vzalloc buffer: ", vzbuf, VMALLOC_BUFFER_SIZE);
	show_vmalloc_mapping("vzalloc", vzbuf, VMALLOC_BUFFER_SIZE);

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

	pr_info("KOOPS_MM loaded\n");
	pr_info("KOOPS_MM current task        : %s [%d]\n", current->comm, current->pid);

	print_global_constants(ram_bytes);

	ret = allocate_page_memory();
	if (ret)
		return ret;

	ret = allocate_slab_memory();
	if (ret) {
		free_page_memory();
		return ret;
	}

	ret = create_custom_slab_cache();
	if (ret) {
		free_slab_memory();
		free_page_memory();
		return ret;
	}

	ret = allocate_vmalloc_memory();
	if (ret) {
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
	print_addr("mm_koops_exit", (unsigned long)mm_koops_exit);
	free_vmalloc_memory();
	free_custom_slab_cache();
	free_slab_memory();
	free_page_memory();
	pr_info("KOOPS_MM allocator study freed\n");
	pr_info("KOOPS_MM unloaded\n");
}

module_init(mm_koops_init);
module_exit(mm_koops_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Manoj study module");
MODULE_DESCRIPTION("Simple x86-64 kernel VAS and allocator study module");
