#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <aio.h>       /* aio_write(), aio_error(), aio_return(), aio_suspend(); POSIX asynchronous I/O control blocks */
#include <errno.h>     /* errno for syscall failures; EEXIST for mkdir() when the data directory already exists */
#include <fcntl.h>     /* open(), posix_fadvise(), readahead(), and file status flags such as O_RDONLY and O_RDWR */
#include <limits.h>    /* IOV_MAX; the kernel-enforced upper bound for iovec segment counts */
#include <stdint.h>    /* uintptr_t for page-alignment checks when describing mmap() results */
#include <stdio.h>     /* printf(), fprintf(), perror(); stdio used for readable demo output */
#include <stdlib.h>    /* malloc(), free(), EXIT_FAILURE; general memory and process utilities */
#include <string.h>    /* memset(), memcpy(), strlen(), strerror(); byte operations and readable error strings */
#include <sys/epoll.h> /* epoll_create1(), epoll_ctl(), epoll_wait(), and struct epoll_event */
#include <sys/mman.h>  /* mmap(), munmap(), msync(), mprotect(), madvise(), mremap(); memory-mapped file interfaces */
#include <sys/stat.h>  /* mkdir(), fstat(), and mode constants such as 0644 and 0755 */
#include <sys/types.h> /* common POSIX system data types such as off_t and ssize_t */
#include <sys/uio.h>   /* readv(), writev(), and struct iovec for scatter/gather I/O */
#include <time.h>      /* struct timespec used with aio_suspend() timeout handling */
#include <unistd.h>    /* close(), ftruncate(), fsync(), pipe(), pread(), pwrite(), getpagesize() */

/*
    Small Linux advanced file-I/O demonstrations.

    The examples cover:
      - writev(), readv() for scatter/gather I/O
      - epoll_create1(), epoll_ctl(), epoll_wait() with pipes
      - mmap(), msync(), mprotect(), mremap(), munmap()
      - posix_fadvise(), madvise(), readahead()
      - aio_write(), aio_error(), aio_suspend(), aio_return()

    Topics such as disk schedulers are kernel policy rather than a process-local API,
    so they are discussed conceptually but not demonstrated directly here.
*/

static int ensure_data_dir(void)
{
    if (mkdir("data", 0755) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "main: mkdir(\"data\") failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int close_checked(int fd, const char *label)
{
    if (close(fd) == -1)
    {
        fprintf(stderr, "%s: close failed: %s\n", label, strerror(errno));
        return -1;
    }
    return 0;
}

static int set_nonblocking(int fd, const char *label)
{
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
    {
        fprintf(stderr, "%s: fcntl(F_GETFL) failed: %s\n", label, strerror(errno));
        return -1;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        fprintf(stderr, "%s: fcntl(F_SETFL, O_NONBLOCK) failed: %s\n", label, strerror(errno));
        return -1;
    }

    return 0;
}

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;

    while (len > 0)
    {
        ssize_t n = write(fd, p, len);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }

    return 0;
}

static ssize_t read_retry(int fd, void *buf, size_t len)
{
    for (;;)
    {
        ssize_t n = read(fd, buf, len);
        if (n < 0 && errno == EINTR)
            continue;
        return n;
    }
}

/*
    Demo 1: scatter/gather I/O.

    writev() drains each iovec in order with one syscall.
    readv() fills each iovec in order with one syscall.

    The file is still one linear byte stream.
    The vector is only a user-space way to describe multiple disjoint buffers to one read or write operation.
*/
static void demo_scatter_gather(const char *filename)
{
    printf("\n------ 1. Scatter/Gather I/O: writev() and readv() ------\n");
    printf("scatter_gather: target file = %s\n", filename);
    printf("scatter_gather: IOV_MAX on this system = %ld\n", (long)IOV_MAX);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "scatter_gather: open for write failed: %s\n", strerror(errno));
        return;
    }

    char header[] = "header: advanced file I/O\n";
    char body[] = "body: writev() sends disjoint buffers in one syscall\n";
    char footer[] = "footer: one stream, three buffers\n";
    struct iovec out[3];

    out[0].iov_base = header;
    out[0].iov_len = strlen(header);
    out[1].iov_base = body;
    out[1].iov_len = strlen(body);
    out[2].iov_base = footer;
    out[2].iov_len = strlen(footer);

    ssize_t written = writev(fd, out, 3);
    if (written < 0)
    {
        fprintf(stderr, "scatter_gather: writev failed: %s\n", strerror(errno));
        close_checked(fd, "scatter_gather(write)");
        return;
    }
    printf("scatter_gather: writev() wrote %zd bytes from 3 buffers\n", written);

    if (close_checked(fd, "scatter_gather(write)") == -1)
        return;

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "scatter_gather: open for read failed: %s\n", strerror(errno));
        return;
    }

    char in_header[sizeof(header)] = {0};
    char in_body[sizeof(body)] = {0};
    char in_tail[sizeof(footer)] = {0};
    struct iovec in[3];

    in[0].iov_base = in_header;
    in[0].iov_len = strlen(header);
    in[1].iov_base = in_body;
    in[1].iov_len = strlen(body);
    in[2].iov_base = in_tail;
    in[2].iov_len = strlen(footer);

    ssize_t nread = readv(fd, in, 3);
    if (nread < 0)
    {
        fprintf(stderr, "scatter_gather: readv failed: %s\n", strerror(errno));
        close_checked(fd, "scatter_gather(read)");
        return;
    }

    printf("scatter_gather: readv() read %zd bytes into 3 buffers\n", nread);
    printf("scatter_gather: buffer 0 = \"%s\"\n", in_header);
    printf("scatter_gather: buffer 1 = \"%s\"\n", in_body);
    printf("scatter_gather: buffer 2 = \"%s\"\n", in_tail);

    close_checked(fd, "scatter_gather(read)");
}

/*
    Demo 2: epoll.

    epoll decouples registration from waiting.
    We register two pipe read ends once, then wait for readiness notifications.

    Like select() and poll(), epoll does not move the bytes itself.
    It scales the "which fd is ready?" question for larger sets of descriptors.
*/
static void demo_epoll(void)
{
    printf("\n------ 2. Event Poll: epoll_create1(), epoll_ctl(), epoll_wait() ------\n");

    int epfd = epoll_create1(0);
    if (epfd == -1)
    {
        fprintf(stderr, "epoll: epoll_create1 failed: %s\n", strerror(errno));
        return;
    }
    printf("epoll: created epoll instance on fd %d\n", epfd);

    int pipe_a[2] = {-1, -1};
    int pipe_b[2] = {-1, -1};

    if (pipe(pipe_a) == -1 || pipe(pipe_b) == -1)
    {
        fprintf(stderr, "epoll: pipe failed: %s\n", strerror(errno));
        if (pipe_a[0] != -1)
            close_checked(pipe_a[0], "epoll");
        if (pipe_a[1] != -1)
            close_checked(pipe_a[1], "epoll");
        if (pipe_b[0] != -1)
            close_checked(pipe_b[0], "epoll");
        if (pipe_b[1] != -1)
            close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    if (set_nonblocking(pipe_a[0], "epoll(pipe_a)") == -1 ||
        set_nonblocking(pipe_b[0], "epoll(pipe_b)") == -1)
    {
        close_checked(pipe_a[0], "epoll");
        close_checked(pipe_a[1], "epoll");
        close_checked(pipe_b[0], "epoll");
        close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.fd = pipe_a[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_a[0], &ev) == -1)
    {
        fprintf(stderr, "epoll: EPOLL_CTL_ADD for pipe_a failed: %s\n", strerror(errno));
        close_checked(pipe_a[0], "epoll");
        close_checked(pipe_a[1], "epoll");
        close_checked(pipe_b[0], "epoll");
        close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = pipe_b[0];
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_b[0], &ev) == -1)
    {
        fprintf(stderr, "epoll: EPOLL_CTL_ADD for pipe_b failed: %s\n", strerror(errno));
        close_checked(pipe_a[0], "epoll");
        close_checked(pipe_a[1], "epoll");
        close_checked(pipe_b[0], "epoll");
        close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    printf("epoll: registered pipe_a with level-triggered EPOLLIN\n");
    printf("epoll: registered pipe_b with edge-triggered EPOLLIN | EPOLLET\n");

    if (write_all(pipe_a[1], "A: ready through level trigger\n", 30) == -1 ||
        write_all(pipe_b[1], "B: ready through edge trigger\n", 29) == -1)
    {
        fprintf(stderr, "epoll: write to seed pipes failed: %s\n", strerror(errno));
        close_checked(pipe_a[0], "epoll");
        close_checked(pipe_a[1], "epoll");
        close_checked(pipe_b[0], "epoll");
        close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    struct epoll_event events[4];
    int ready = epoll_wait(epfd, events, 4, 1000);
    if (ready == -1)
    {
        fprintf(stderr, "epoll: epoll_wait failed: %s\n", strerror(errno));
        close_checked(pipe_a[0], "epoll");
        close_checked(pipe_a[1], "epoll");
        close_checked(pipe_b[0], "epoll");
        close_checked(pipe_b[1], "epoll");
        close_checked(epfd, "epoll");
        return;
    }

    printf("epoll: epoll_wait() returned %d ready events\n", ready);
    for (int i = 0; i < ready; ++i)
    {
        char buf[64];
        ssize_t n = read_retry(events[i].data.fd, buf, sizeof(buf) - 1);
        if (n < 0)
        {
            if (errno == EAGAIN)
            {
                printf("epoll: fd %d reported readiness but no bytes remained\n", events[i].data.fd);
                continue;
            }
            fprintf(stderr, "epoll: read after epoll_wait failed: %s\n", strerror(errno));
            continue;
        }

        buf[n] = '\0';
        printf("epoll: fd %d events=0x%x data=\"%s\"\n",
               events[i].data.fd, events[i].events, buf);
    }

    if (epoll_ctl(epfd, EPOLL_CTL_DEL, pipe_a[0], NULL) == -1)
        fprintf(stderr, "epoll: EPOLL_CTL_DEL for pipe_a failed: %s\n", strerror(errno));
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, pipe_b[0], NULL) == -1)
        fprintf(stderr, "epoll: EPOLL_CTL_DEL for pipe_b failed: %s\n", strerror(errno));

    close_checked(pipe_a[0], "epoll");
    close_checked(pipe_a[1], "epoll");
    close_checked(pipe_b[0], "epoll");
    close_checked(pipe_b[1], "epoll");
    close_checked(epfd, "epoll");
}

/*
    Demo 3: memory-mapped I/O.

    MAP_SHARED makes writes visible to the underlying file.
    mprotect() changes access permissions on the mapping.
    mremap() can grow the mapping after the file itself is enlarged.

    The file's bytes can be exposed through memory pages instead of explicit
    read()/write() calls.
*/
static void demo_mmap(const char *filename)
{
    printf("\n------ 3. Memory-Mapped I/O: mmap(), msync(), mprotect(), mremap() ------\n");
    printf("mmap: target file = %s\n", filename);

    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "mmap: open failed: %s\n", strerror(errno));
        return;
    }

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0)
    {
        fprintf(stderr, "mmap: sysconf(_SC_PAGESIZE) failed: %s\n", strerror(errno));
        close_checked(fd, "mmap");
        return;
    }
    printf("mmap: page size = %ld bytes\n", page_size);

    if (ftruncate(fd, page_size) == -1)
    {
        fprintf(stderr, "mmap: ftruncate to one page failed: %s\n", strerror(errno));
        close_checked(fd, "mmap");
        return;
    }

    char *map = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
    {
        fprintf(stderr, "mmap: mmap failed: %s\n", strerror(errno));
        close_checked(fd, "mmap");
        return;
    }

    printf("mmap: mapping address = %p\n", (void *)map);
    printf("mmap: mapping address modulo page size = %lu\n",
           (unsigned long)((uintptr_t)map % (uintptr_t)page_size));

    const char *msg = "Mapped bytes written through MAP_SHARED\n";
    memcpy(map, msg, strlen(msg));
    printf("mmap: copied %zu bytes directly into the mapped region\n", strlen(msg));

    if (msync(map, (size_t)page_size, MS_SYNC) == -1)
    {
        fprintf(stderr, "mmap: msync(MS_SYNC) failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size);
        close_checked(fd, "mmap");
        return;
    }
    printf("mmap: msync(MS_SYNC) pushed dirty pages toward storage\n");

    if (mprotect(map, (size_t)page_size, PROT_READ) == -1)
    {
        fprintf(stderr, "mmap: mprotect(PROT_READ) failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size);
        close_checked(fd, "mmap");
        return;
    }
    printf("mmap: mprotect() changed the mapping to read-only\n");

    if (ftruncate(fd, (off_t)page_size * 2) == -1)
    {
        fprintf(stderr, "mmap: ftruncate to two pages failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size);
        close_checked(fd, "mmap");
        return;
    }

    char *grown = mremap(map, (size_t)page_size, (size_t)page_size * 2, MREMAP_MAYMOVE);
    if (grown == MAP_FAILED)
    {
        fprintf(stderr, "mmap: mremap failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size);
        close_checked(fd, "mmap");
        return;
    }
    map = grown;
    printf("mmap: mremap() grew the mapping from %ld to %ld bytes\n", page_size, page_size * 2);

    if (mprotect(map, (size_t)page_size * 2, PROT_READ | PROT_WRITE) == -1)
    {
        fprintf(stderr, "mmap: mprotect(PROT_READ | PROT_WRITE) after growth failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size * 2);
        close_checked(fd, "mmap");
        return;
    }

    const char *tail = "Second page added through mremap()\n";
    memcpy(map + page_size, tail, strlen(tail));
    if (msync(map + page_size, (size_t)page_size, MS_SYNC) == -1)
    {
        fprintf(stderr, "mmap: second msync failed: %s\n", strerror(errno));
        munmap(map, (size_t)page_size * 2);
        close_checked(fd, "mmap");
        return;
    }
    printf("mmap: wrote into the second page after growing the mapping\n");

    if (munmap(map, (size_t)page_size * 2) == -1)
        fprintf(stderr, "mmap: munmap failed: %s\n", strerror(errno));

    close_checked(fd, "mmap");
}

/*
    Demo 4: access-pattern advice.

    posix_fadvise() hints on file descriptors.
    madvise() hints on memory mappings.
    readahead() asks Linux to start populating the page cache for a range.

    These are hints, not correctness rules.
    They try to help the kernel manage the page-cache and paging behavior more effectively for expected access patterns.
*/
static void demo_advice(const char *filename)
{
    printf("\n------ 4. File and Mapping Advice: posix_fadvise(), madvise(), readahead() ------\n");
    printf("advice: target file = %s\n", filename);

    int fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "advice: open failed: %s\n", strerror(errno));
        return;
    }

    const char *payload =
        "This file exists to demonstrate cache and readahead advice.\n"
        "The advice calls are hints, not correctness requirements.\n";

    if (write_all(fd, payload, strlen(payload)) == -1)
    {
        fprintf(stderr, "advice: initial write failed: %s\n", strerror(errno));
        close_checked(fd, "advice");
        return;
    }

    int rc = posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
    if (rc != 0)
        fprintf(stderr, "advice: posix_fadvise(SEQUENTIAL) failed: %s\n", strerror(rc));
    else
        printf("advice: posix_fadvise(..., POSIX_FADV_SEQUENTIAL) accepted\n");

    rc = posix_fadvise(fd, 0, 0, POSIX_FADV_WILLNEED);
    if (rc != 0)
        fprintf(stderr, "advice: posix_fadvise(WILLNEED) failed: %s\n", strerror(rc));
    else
        printf("advice: posix_fadvise(..., POSIX_FADV_WILLNEED) accepted\n");

    if (readahead(fd, 0, 64) == -1)
        fprintf(stderr, "advice: readahead(0, 64) failed: %s\n", strerror(errno));
    else
        printf("advice: readahead(fd, 0, 64) requested page-cache population\n");

    off_t size = lseek(fd, 0, SEEK_END);
    if (size == (off_t)-1)
    {
        fprintf(stderr, "advice: lseek(SEEK_END) failed: %s\n", strerror(errno));
        close_checked(fd, "advice");
        return;
    }

    char *map = mmap(NULL, (size_t)size, PROT_READ, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED)
    {
        fprintf(stderr, "advice: mmap failed: %s\n", strerror(errno));
        close_checked(fd, "advice");
        return;
    }

    if (madvise(map, (size_t)size, MADV_SEQUENTIAL) == -1)
        fprintf(stderr, "advice: madvise(MADV_SEQUENTIAL) failed: %s\n", strerror(errno));
    else
        printf("advice: madvise(..., MADV_SEQUENTIAL) accepted on the mapping\n");

    if (madvise(map, (size_t)size, MADV_WILLNEED) == -1)
        fprintf(stderr, "advice: madvise(MADV_WILLNEED) failed: %s\n", strerror(errno));
    else
        printf("advice: madvise(..., MADV_WILLNEED) accepted on the mapping\n");

    if (madvise(map, (size_t)size, MADV_DONTNEED) == -1)
        fprintf(stderr, "advice: madvise(MADV_DONTNEED) failed: %s\n", strerror(errno));
    else
        printf("advice: madvise(..., MADV_DONTNEED) asked the kernel to drop those cached pages when practical\n");

    if (munmap(map, (size_t)size) == -1)
        fprintf(stderr, "advice: munmap failed: %s\n", strerror(errno));

    close_checked(fd, "advice");
}

/*
    Demo 5: POSIX AIO.

    aio_write() submits work and returns immediately.
    Completion still means "finished with the kernel request", not "physically on disk".

    This changes when the calling thread blocks;
    it does not remove the kernel's buffered I/O and durability rules described in the earlier examples.
*/
static void demo_aio(const char *filename)
{
    printf("\n------ 5. Asynchronous I/O: aio_write(), aio_suspend(), aio_return() ------\n");
    printf("aio: target file = %s\n", filename);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "aio: open failed: %s\n", strerror(errno));
        return;
    }

    char buffer[] =
        "AIO submitted this write without blocking for the whole request.\n";

    struct aiocb cb;
    memset(&cb, 0, sizeof(cb));
    cb.aio_fildes = fd;
    cb.aio_buf = buffer;
    cb.aio_nbytes = strlen(buffer);
    cb.aio_offset = 0;

    if (aio_write(&cb) == -1)
    {
        fprintf(stderr, "aio: aio_write failed: %s\n", strerror(errno));
        close_checked(fd, "aio");
        return;
    }
    printf("aio: aio_write() submitted %zu bytes and returned immediately\n", cb.aio_nbytes);

    const struct aiocb *list[1] = {&cb};
    struct timespec timeout;
    timeout.tv_sec = 1;
    timeout.tv_nsec = 0;

    if (aio_suspend(list, 1, &timeout) == -1 && errno != EINTR)
    {
        fprintf(stderr, "aio: aio_suspend failed: %s\n", strerror(errno));
        close_checked(fd, "aio");
        return;
    }

    int err = aio_error(&cb);
    if (err == EINPROGRESS)
    {
        fprintf(stderr, "aio: request still in progress after aio_suspend timeout\n");
        close_checked(fd, "aio");
        return;
    }
    if (err != 0)
    {
        fprintf(stderr, "aio: request completed with error: %s\n", strerror(err));
        close_checked(fd, "aio");
        return;
    }

    ssize_t written = aio_return(&cb);
    if (written < 0)
    {
        fprintf(stderr, "aio: aio_return reported failure\n");
        close_checked(fd, "aio");
        return;
    }
    printf("aio: aio_return() reported %zd bytes written\n", written);

    if (fsync(fd) == -1)
        fprintf(stderr, "aio: fsync failed: %s\n", strerror(errno));
    else
        printf("aio: fsync() requested durable writeback after asynchronous completion\n");

    close_checked(fd, "aio");
}

int main(void)
{
    const char *vectored_file = "data/04-demo_vectored_io.txt";
    const char *mmap_file = "data/04-demo_mmap.txt";
    const char *advice_file = "data/04-demo_advice.txt";
    const char *aio_file = "data/04-demo_aio.txt";

    printf("Starting advanced file-I/O demonstrations.\n");
    if (ensure_data_dir() == -1)
        return 1;

    demo_scatter_gather(vectored_file);
    demo_epoll();
    demo_mmap(mmap_file);
    demo_advice(advice_file);
    demo_aio(aio_file);

    printf("\nAll advanced file-I/O demonstrations completed.\n");
    return 0;
}
