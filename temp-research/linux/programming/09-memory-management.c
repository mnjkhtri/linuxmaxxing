#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/*
    Small Linux memory management demonstrations.

    The examples cover:
      - Process address space: segment locations from /proc/self/maps
      - Copy-on-Write: fork proves virtual addresses diverge physically on write
      - malloc(), calloc(), realloc(), free(), malloc_usable_size()
      - struct padding revealed by sizeof and offsetof
      - mmap(MAP_ANONYMOUS): anonymous mappings that bypass the heap
      - memset(), memmove(), memcmp(): raw memory operations
*/

/* objects that land in different segments */
static int segment_data = 42; /* .data  — initialized global */
static int segment_bss;       /* .bss   — zero global, COW-mapped to a zero page */
static int cow_var = 100;     /* .data  — used for the COW demo */
static void text_fn(void) {}  /* .text  — executable code */

/*
    Demo 1: process address space.

    Prints the virtual address of one object from each major segment.
    On x86-64 Linux the ordering is typically:
      text < rodata < .data/.bss < heap < mmap regions < stack
    /proc/self/maps confirms the layout with permission bits (r-xp for text, rw-p for data/heap/stack).
*/
static void demo_address_space(void)
{
    printf("\n------ 1. Address space: segment locations ------\n");

    int stack_var = 0;
    void *heap_ptr = malloc(64);
    void *mmap_ptr = mmap(NULL, (size_t)getpagesize(), PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("addrspace: .text  (function)    0x%lx\n", (unsigned long)(uintptr_t)text_fn);
    printf("addrspace: .rodata (literal)    %p\n", (void *)"hello");
    printf("addrspace: .data  (init global) %p  val=%d\n", (void *)&segment_data, segment_data);
    printf("addrspace: .bss   (zero global) %p  val=%d\n", (void *)&segment_bss, segment_bss);
    printf("addrspace: heap   (malloc)      %p\n", heap_ptr);
    printf("addrspace: mmap   (anonymous)   %p\n", mmap_ptr != MAP_FAILED ? mmap_ptr : NULL);
    printf("addrspace: stack  (local var)   %p\n", (void *)&stack_var);
    printf("addrspace: page size            %d bytes\n", getpagesize());

    printf("\naddrspace: /proc/self/maps (own segments, shared libs omitted):\n");
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp)
    {
        char line[256];
        while (fgets(line, sizeof(line), fp))
            if (!strstr(line, ".so") && !strstr(line, "ld-linux"))
                printf("  %s", line);
        fclose(fp);
    }

    free(heap_ptr);
    if (mmap_ptr != MAP_FAILED)
        munmap(mmap_ptr, (size_t)getpagesize());
}

/*
    Demo 2: Copy-on-Write.

    After fork(), parent and child share the same physical page for cow_var — both print the same virtual address.
    When the child writes, the MMU faults and the kernel silently copies that physical page for the child alone.
    The parent's physical copy is untouched, so it still reads the old value.
*/
static void demo_cow(void)
{
    printf("\n------ 2. Copy-on-Write: fork + write ------\n");
    printf("cow: parent  &cow_var=%p  value=%d\n", (void *)&cow_var, cow_var);

    fflush(stdout); /* flush before fork so the child doesn't re-emit buffered parent output */
    pid_t child = fork();
    if (child == 0)
    {
        printf("cow: child   &cow_var=%p  value=%d  (same virtual address, shared page)\n",
               (void *)&cow_var, cow_var);
        cow_var = 999;
        printf("cow: child   after write: %d  (kernel copied the page for us)\n", cow_var);
        fflush(stdout);
        _exit(0);
    }
    wait(NULL);
    printf("cow: parent  after child write: %d  (own physical page unchanged)\n", cow_var);
}

/*
    Demo 3: dynamic allocation.

    malloc() returns uninitialized memory;
    calloc() zeroes it.
    realloc() grows a block in place if possible, otherwise allocates a new region, copies the old data, and frees the original.
    malloc_usable_size() reveals the true allocated size after alignment rounding.

*/
static void demo_allocation(void)
{
    printf("\n------ 3. Dynamic allocation: malloc, calloc, realloc ------\n");

    char *a = malloc(64);
    printf("alloc: malloc(64)    usable=%-4zu  (contents undefined)\n",
           malloc_usable_size(a));

    char *b = calloc(1, 64);
    printf("alloc: calloc(64)    usable=%-4zu  first byte=0x%02x (zeroed)\n",
           malloc_usable_size(b), (unsigned char)b[0]);
    free(b);

    strcpy(a, "hello");
    char *c = realloc(a, 256);
    printf("alloc: realloc(256)  usable=%-4zu  data preserved: \"%s\"\n",
           malloc_usable_size(c), c);
    free(c);

    /* ask for 1 byte, get a full alignment unit back */
    char *tiny = malloc(1);
    printf("alloc: malloc(1)     usable=%-4zu  (allocator rounds up)\n",
           malloc_usable_size(tiny));
    free(tiny);
}

/*
    Demo 2: struct padding and alignment.

    The compiler inserts invisible padding between struct members so each field starts at its natural alignment boundary.
    offsetof() exposes where each member actually sits.
    posix_memalign() allocates on an explicit power-of-two boundary, needed for things like direct block I/O.
*/
struct gapped
{
    char a;
    int b;
    char c;
};
struct ordered
{
    char a;
    char b;
    char c;
    char d;
    int e;
};

static void demo_alignment(void)
{
    printf("\n------ 4. Alignment: struct padding, posix_memalign ------\n");

    printf("alignment: struct { char a; int b; char c }  "
           "sizeof=%zu  (not %zu — padding added)\n",
           sizeof(struct gapped),
           sizeof(char) + sizeof(int) + sizeof(char));
    printf("alignment: offsets  a=%zu  b=%zu  c=%zu\n",
           offsetof(struct gapped, a),
           offsetof(struct gapped, b),
           offsetof(struct gapped, c));

    printf("alignment: struct { char[4]; int }           "
           "sizeof=%zu  (no padding needed)\n",
           sizeof(struct ordered));

    void *p;
    if (posix_memalign(&p, 4096, 4096) == 0)
    {
        printf("alignment: posix_memalign(4096)  addr=%p  page-aligned=%s\n",
               p, ((unsigned long)p % 4096 == 0) ? "yes" : "no");
        free(p);
    }
}

/*
    Demo 3: anonymous mmap.

    For large allocations glibc bypasses the heap and calls mmap() directly.
    MAP_ANONYMOUS | MAP_PRIVATE gives a private, zero-filled region backed only by virtual address space.
    munmap() returns the pages to the kernel immediately — unlike free(), which may hold them in the heap for reuse.
*/
static void demo_mmap(void)
{
    printf("\n------ 5. Anonymous mmap: MAP_ANONYMOUS | MAP_PRIVATE ------\n");

    size_t size = (size_t)getpagesize();
    char *m = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
    {
        fprintf(stderr, "mmap: failed\n");
        return;
    }

    int all_zero = 1;
    for (size_t i = 0; i < size; ++i)
        if (m[i] != 0)
        {
            all_zero = 0;
            break;
        }

    printf("mmap: mapped %zu bytes at %p\n", size, (void *)m);
    printf("mmap: zero-filled on arrival: %s\n", all_zero ? "yes" : "no");

    strcpy(m, "written to anonymous mapping");
    printf("mmap: after write: \"%s\"\n", m);

    munmap(m, size);
    printf("mmap: munmap() returned pages to kernel immediately\n");
}

/*
    Demo 4: raw memory operations.

    memset fills every byte to a value.
    memmove correctly handles overlapping source and destination regions by copying in the safe direction;
    memcpy forbids overlap and is undefined behaviour if regions touch.
    memcmp compares bytes — it must not be used on structs because padding bytes between members are uninitialized.
*/
static void demo_memops(void)
{
    printf("\n------ 6. Memory ops: memset, memmove, memcmp ------\n");

    char buf[16];
    memset(buf, 0xAB, sizeof(buf));
    printf("memops: memset(0xAB)  buf[0]=0x%02x  buf[15]=0x%02x\n",
           (unsigned char)buf[0], (unsigned char)buf[15]);

    /* memmove: src (s+2) and dst (s+3) overlap — safe because it copies from right to left when dst > src */
    char s[] = "0123456789";
    printf("memops: before memmove: \"%s\"\n", s);
    memmove(s + 3, s + 2, 5);
    printf("memops: after  memmove(dst=s+3, src=s+2, n=5): \"%s\"\n", s);

    char x[] = "abc";
    char y[] = "abd";
    printf("memops: memcmp(\"abc\",\"abd\",3) = %d  (negative means x < y)\n",
           memcmp(x, y, 3));
}

int main(void)
{
    printf("Starting memory management demonstrations.\n");

    demo_address_space();
    demo_cow();
    demo_allocation();
    demo_alignment();
    demo_mmap();
    demo_memops();

    printf("\nAll memory management demonstrations completed.\n");
    return EXIT_SUCCESS;
}
