#define _GNU_SOURCE /* Exposes GNU/Linux extensions such as O_DIRECT on glibc systems. */

#include <fcntl.h>      /* open(); access and status flags: O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_DIRECT */
#include <poll.h>       /* poll(); struct pollfd; readiness/event flags such as POLLIN and the revents field */
#include <sys/select.h> /* select(); fd_set; FD_ZERO(), FD_SET(), FD_ISSET(); struct timeval timeout used by select() */
#include <sys/stat.h>   /* truncate() declaration plus file metadata and mode definitions associated with file operations */
#include <unistd.h>     /* read(), write(), close(), lseek(), pread(), pwrite(), pipe(), ftruncate(), fsync(), fdatasync(), sync() */
#include <errno.h>      /* errno for syscall failures; EINTR for interrupted system calls */
#include <dirent.h>     /* opendir(), readdir(), closedir(); inspect /proc/self/fd */
#include <stdio.h>      /* printf() and fprintf() for demo output; stderr for error reporting */
#include <stdlib.h>     /* free() for cleanup; posix_memalign() for aligned O_DIRECT buffers */
#include <string.h>     /* strlen(), memcpy(), memset(); strerror() to convert error codes into readable text */

/*
    Small Linux file-I/O demonstrations with strict error handling.

    The examples cover:
      - open(), read(), write(), close()
      - lseek(), pread(), pwrite()
      - truncate(), ftruncate()
      - fdatasync(), fsync(), sync()
      - select(), poll()
      - O_DIRECT

    The goal is to show the model behind each call, not just a syscall sequence.
    At the syscall level, read() and write() move bytes. If those bytes happen to
    represent text, we may print them as characters, but the kernel is dealing in
    raw byte counts.
*/

/* close() can report deferred writeback errors, so cleanup is checked too. */
static int close_checked(int fd, const char *label)
{
    if (close(fd) == -1)
    {
        fprintf(stderr, "%s: close failed: %s\n", label, strerror(errno));
        return -1;
    }
    return 0;
}

/*
    Keep calling write() until the full buffer is written or a real error occurs.
    Retry transparently if the call is interrupted by a signal.
*/
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

/* Preserve normal read() behavior, but retry on EINTR. */
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

/* Create the data directory used for generated demo files if it is missing. */
static int ensure_data_dir(void)
{
    if (mkdir("data", 0755) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "main: mkdir(\"data\") failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/*
    Print the descriptors currently open in this process.
    On a typical terminal run, 0/1/2 are stdin/stdout/stderr, so the next open() often returns 3.
*/
static void show_open_fds(void)
{
    DIR *dir = opendir("/proc/self/fd");
    if (dir == NULL)
    {
        fprintf(stderr, "main: unable to inspect /proc/self/fd: %s\n", strerror(errno));
        return;
    }

    printf("\n------ 0. Process startup: existing file descriptors ------\n");
    printf("main: open file descriptors at startup:\n");
    printf("main: opendir(\"/proc/self/fd\") adds a temporary directory descriptor during this listing\n");
    printf("main: that temporary descriptor often appears as fd 3\n");

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        printf("  fd %s\n", entry->d_name);
    }

    closedir(dir);
    printf("main: stdin=0, stdout=1, stderr=2 are normally open already\n");
    printf("main: after closedir(), the temporary descriptor is released\n");
    printf("main: the first later open() often reuses fd 3\n");
}

/*
    Demo 1: basic descriptor lifecycle.

    Open a file, write data, close it, reopen it for reading, and read it back.
    The read side is intentionally bounded so the demo can show partial reads and explicit truncation handling.

    The pathname is resolved through VFS, the inode identifies the file object,
    and read()/write() operate on the file's bytes.
*/
static void demo_basic_io(const char *filename)
{
    printf("\n------ 1. Basic I/O: open, write, close, robust read ------\n");
    printf("basic_io: target file = %s\n", filename);
    printf("basic_io: read() and write() move bytes; text is one byte-level interpretation\n");

    const char *msg = "Learning Linux System Programming!\n";

    /*
        O_WRONLY: write-only access
        O_CREAT: create the file if needed
        O_TRUNC: reset an existing regular file to length 0

        Mode 0644 still passes through the process umask.
    */
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "basic_io: open for write failed: %s\n", strerror(errno));
        return;
    }
    printf("basic_io: opened %s for write on fd %d\n", filename, fd);
    printf("basic_io: writing %zu bytes\n", strlen(msg));

    if (write_all(fd, msg, strlen(msg)) == -1)
    {
        fprintf(stderr, "basic_io: write failed: %s\n", strerror(errno));
        close_checked(fd, "basic_io(write path)");
        return;
    }

    if (close_checked(fd, "basic_io(write path)") == -1)
        return;
    printf("basic_io: closed write descriptor\n");

    fd = open(filename, O_RDONLY);
    if (fd == -1)
    {
        fprintf(stderr, "basic_io: open for read failed: %s\n", strerror(errno));
        return;
    }
    printf("basic_io: reopened %s for read on fd %d\n", filename, fd);

    char buffer[256];
    size_t total = 0;
    int truncated = 0;

    /* Read until EOF or until the demo buffer is full. */
    while (total < sizeof(buffer) - 1)
    {
        ssize_t n = read_retry(fd, buffer + total, sizeof(buffer) - 1 - total);
        if (n < 0)
        {
            fprintf(stderr, "basic_io: read failed: %s\n", strerror(errno));
            close_checked(fd, "basic_io(read path)");
            return;
        }
        if (n == 0)
            break;
        total += (size_t)n;
        printf("basic_io: read chunk of %zd bytes (total so far: %zu)\n", n, total);
    }

    /* Probe one extra byte so truncation is reported instead of hidden. */
    if (total == sizeof(buffer) - 1)
    {
        char scratch[1];
        ssize_t n = read_retry(fd, scratch, sizeof(scratch));
        if (n > 0)
            truncated = 1;
        else if (n < 0)
        {
            fprintf(stderr, "basic_io: final read failed: %s\n", strerror(errno));
            close_checked(fd, "basic_io(read path)");
            return;
        }
    }

    buffer[total] = '\0';
    printf("basic_io: read back %zu bytes: %s", total, buffer);
    if (truncated)
        printf("basic_io: output truncated to %zu bytes\n", sizeof(buffer) - 1);

    close_checked(fd, "basic_io(read path)");
}

/*
    Demo 2: synchronization calls.

    write() usually copies data into kernel-managed buffers first.
    fdatasync(), fsync(), and sync() show different ways to push dirty data toward storage.

    A successful write() usually means "the kernel accepted the bytes", not
    "the storage device finished the write".
*/
static void demo_sync(const char *filename)
{
    printf("\n------ 2. Synchronization: fdatasync, fsync, sync ------\n");
    printf("sync: target file = %s\n", filename);

    /* O_APPEND moves each write to EOF; O_CREAT keeps the demo self-contained. */
    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "sync: open failed: %s\n", strerror(errno));
        return;
    }
    printf("sync: opened %s for append on fd %d\n", filename, fd);

    const char *msg = "Flushing this through sync interfaces.\n";
    printf("sync: appending %zu bytes\n", strlen(msg));
    if (write_all(fd, msg, strlen(msg)) == -1)
    {
        fprintf(stderr, "sync: write failed: %s\n", strerror(errno));
        close_checked(fd, "sync");
        return;
    }

    if (fdatasync(fd) == -1)
    {
        fprintf(stderr, "sync: fdatasync failed: %s\n", strerror(errno));
    }
    else
    {
        printf("sync: fdatasync() completed\n");
    }

    if (fsync(fd) == -1)
    {
        fprintf(stderr, "sync: fsync failed: %s\n", strerror(errno));
    }
    else
    {
        printf("sync: fsync() completed\n");
    }

    /* sync() requests writeback system-wide, not just for this file. */
    sync();
    printf("sync: sync() requested system-wide writeback of dirty buffers\n");

    close_checked(fd, "sync");
}

/*
    Demo 3: file offsets and positional I/O.

    lseek() changes the descriptor's current offset. pread() and pwrite() target
    an explicit position and leave that shared offset unchanged.

    The inode still represents one file object, but each open file description also
    tracks a current offset. pread()/pwrite() bypass that shared offset bookkeeping.
*/
static void demo_position(const char *filename)
{
    printf("\n------ 3. File positioning: lseek, pread, pwrite ------\n");
    printf("position: target file = %s\n", filename);

    int fd = open(filename, O_RDWR);
    if (fd == -1)
    {
        fprintf(stderr, "position: open failed: %s\n", strerror(errno));
        return;
    }
    printf("position: opened %s for read/write on fd %d\n", filename, fd);

    /* lseek(fd, 0, SEEK_END) is a common way to query the current file size. */
    off_t file_size = lseek(fd, 0, SEEK_END);
    if (file_size == (off_t)-1)
    {
        fprintf(stderr, "position: lseek(SEEK_END) failed: %s\n", strerror(errno));
        close_checked(fd, "position");
        return;
    }
    printf("position: size from lseek(SEEK_END) = %lld bytes\n", (long long)file_size);
    printf("position: writing \"UPDATED \" at offset 0 with pwrite()\n");

    /* pwrite() updates bytes at offset 0 without touching the current offset. */
    if (pwrite(fd, "UPDATED ", 8, 0) != 8)
    {
        if (errno != 0)
            fprintf(stderr, "position: pwrite failed: %s\n", strerror(errno));
        else
            fprintf(stderr, "position: pwrite wrote a short count\n");
        close_checked(fd, "position");
        return;
    }

    /* Capture the offset around pread() to show that pread() does not move it. */
    off_t before = lseek(fd, 0, SEEK_CUR);
    if (before == (off_t)-1)
    {
        fprintf(stderr, "position: lseek(SEEK_CUR) failed: %s\n", strerror(errno));
        close_checked(fd, "position");
        return;
    }
    printf("position: offset before pread() = %lld\n", (long long)before);

    char buf[9] = {0};
    ssize_t n = pread(fd, buf, 8, 0);
    if (n < 0)
    {
        fprintf(stderr, "position: pread failed: %s\n", strerror(errno));
        close_checked(fd, "position");
        return;
    }

    off_t after = lseek(fd, 0, SEEK_CUR);
    if (after == (off_t)-1)
    {
        fprintf(stderr, "position: lseek(SEEK_CUR) failed: %s\n", strerror(errno));
        close_checked(fd, "position");
        return;
    }
    printf("position: offset after pread() = %lld\n", (long long)after);

    printf("position: pread() at offset 0 returned \"%.*s\"\n", (int)n, buf);
    printf("position: offset before pread() = %lld, after pread() = %lld\n",
           (long long)before, (long long)after);

    close_checked(fd, "position");
}

/*
    Demo 4: truncation.

    truncate() resizes by path. ftruncate() resizes through an open descriptor.
    The demo also shows that changing file length does not move the current file offset.

    Size is inode metadata, so truncation changes the file's recorded length even
    though we are not "writing payload bytes" in the ordinary read()/write() sense.
*/
static void demo_truncation(const char *filename)
{
    printf("\n------ 4. Truncation: truncate, ftruncate ------\n");
    printf("truncation: target file = %s\n", filename);

    printf("truncation: resizing file to 12 bytes with truncate()\n");
    if (truncate(filename, 12) == -1)
    {
        fprintf(stderr, "truncation: truncate failed: %s\n", strerror(errno));
        return;
    }
    printf("truncation: truncate() resized the file to 12 bytes\n");

    int fd = open(filename, O_RDWR);
    if (fd == -1)
    {
        fprintf(stderr, "truncation: open failed: %s\n", strerror(errno));
        return;
    }
    printf("truncation: opened %s on fd %d\n", filename, fd);

    off_t pos_before = lseek(fd, 3, SEEK_SET);
    if (pos_before == (off_t)-1)
    {
        fprintf(stderr, "truncation: lseek failed: %s\n", strerror(errno));
        close_checked(fd, "truncation");
        return;
    }
    printf("truncation: moved current offset to %lld before ftruncate()\n", (long long)pos_before);

    printf("truncation: resizing file to 8 bytes with ftruncate()\n");
    if (ftruncate(fd, 8) == -1)
    {
        fprintf(stderr, "truncation: ftruncate failed: %s\n", strerror(errno));
        close_checked(fd, "truncation");
        return;
    }

    off_t pos_after = lseek(fd, 0, SEEK_CUR);
    if (pos_after == (off_t)-1)
    {
        fprintf(stderr, "truncation: lseek(SEEK_CUR) failed: %s\n", strerror(errno));
        close_checked(fd, "truncation");
        return;
    }

    printf("truncation: ftruncate() resized the file to 8 bytes; current offset stayed at %lld\n",
           (long long)pos_after);

    close_checked(fd, "truncation");
}

/*
    Demo 5: direct I/O.

    O_DIRECT tries to avoid the page cache, but support is environment-dependent and alignment rules still matter.
    It is not a substitute for fsync() when durability matters.

    Most file I/O goes through the page cache first, while O_DIRECT asks the
    kernel to avoid that path when possible.
*/
static void demo_direct_io(const char *filename)
{
    printf("\n------ 5. Direct I/O: O_DIRECT + aligned buffer ------\n");
    printf("direct_io: target file = %s\n", filename);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC | O_DIRECT, 0644);
    if (fd == -1)
    {
        fprintf(stderr,
                "direct_io: O_DIRECT open failed (%s). This often means the filesystem or device does not support it here.\n",
                strerror(errno));
        return;
    }
    printf("direct_io: opened %s with O_DIRECT on fd %d\n", filename, fd);

    /*
        4096 is a practical demo choice, not a universal rule.
        Real code should verify the actual alignment requirements of the target environment.
    */
    size_t alignment = 4096;
    size_t size = 4096;
    char *aligned_buffer = NULL;
    printf("direct_io: allocating a %zu-byte buffer with %zu-byte alignment\n", size, alignment);

    /* posix_memalign() returns an error code directly instead of using errno. */
    int rc = posix_memalign((void **)&aligned_buffer, alignment, size);
    if (rc != 0)
    {
        fprintf(stderr, "direct_io: posix_memalign failed: %s\n", strerror(rc));
        close_checked(fd, "direct_io");
        return;
    }
    printf("direct_io: aligned buffer allocated at %p\n", (void *)aligned_buffer);

    memset(aligned_buffer, 0, size);
    const char *msg = "This block was written with O_DIRECT.\n";
    memcpy(aligned_buffer, msg, strlen(msg));
    printf("direct_io: copied %zu bytes of demo text into the aligned buffer\n", strlen(msg));

    ssize_t n = write(fd, aligned_buffer, size);
    if (n < 0)
    {
        fprintf(stderr, "direct_io: write failed: %s\n", strerror(errno));
        free(aligned_buffer);
        close_checked(fd, "direct_io");
        return;
    }
    if ((size_t)n != size)
    {
        fprintf(stderr, "direct_io: short write: expected %zu, got %zd\n", size, n);
        free(aligned_buffer);
        close_checked(fd, "direct_io");
        return;
    }

    /* O_DIRECT changes caching behavior; fsync() still matters for durability. */
    if (fsync(fd) == -1)
    {
        fprintf(stderr, "direct_io: fsync failed: %s\n", strerror(errno));
    }
    else
    {
        printf("direct_io: O_DIRECT write completed; fsync() requested durability\n");
    }

    free(aligned_buffer);
    close_checked(fd, "direct_io");
}

/*
    Demo 6: multiplexed I/O with select() and poll().

    Use one pipe for both examples. After select() reads the first message, we
    write a second message into the same pipe so poll() has fresh data to detect.

    A pipe is a simple readiness source inside one process: once we write bytes to the write end, the read end becomes readable.
    Think of it as a FIFO byte stream: one fd writes bytes in, the other reads them out, and read bytes are consumed.
    That lets us demonstrate select() and poll() without needing user input, sockets, or another process.

    These calls do not move file data themselves; they tell us when an I/O object is
    ready so we can avoid blocking in the wrong read() or write() call.
*/
static void demo_multiplexing(void)
{
    printf("\n------ 6. Multiplexed I/O: select and poll on pipes ------\n");

    int p[2] = {-1, -1};

    /*
        pipe(fd_pair) fills the array with:
          fd_pair[0] -> read end
          fd_pair[1] -> write end

        After data is written to fd_pair[1], fd_pair[0] becomes readable.
        That is the condition we wait for with select() and poll().
    */
    if (pipe(p) == -1)
    {
        fprintf(stderr, "multiplexing: pipe failed: %s\n", strerror(errno));
        if (p[0] != -1)
            close_checked(p[0], "multiplexing");
        if (p[1] != -1)
            close_checked(p[1], "multiplexing");
        return;
    }
    printf("multiplexing: shared pipe read=%d write=%d\n", p[0], p[1]);

    const char *msg = "hello from pipe";

    /*
        Seed the pipe with data before waiting.
        That guarantees the read end is already readable, so select() should return immediately instead of timing out.
    */
    if (write_all(p[1], msg, strlen(msg)) == -1)
    {
        fprintf(stderr, "multiplexing: write to pipe failed: %s\n", strerror(errno));
        close_checked(p[0], "multiplexing");
        close_checked(p[1], "multiplexing");
        return;
    }
    printf("multiplexing: wrote \"%s\" to the pipe before select()\n", msg);

    /*
        select() uses fd_set bitmaps, requires highest_fd + 1, and rewrites the sets in place.
        It is older, but still common enough to be worth knowing.

        Here we watch only one descriptor: the read end of p.
        If that read end has at least one byte available, select() marks it as readable.
    */
    fd_set rfds;

    /* Start with an empty set, then add the descriptor we care about. */
    FD_ZERO(&rfds);
    FD_SET(p[0], &rfds);

    /*
        Wait at most 1 seconds. Because we already wrote into the pipe, the expected outcome is readiness, not timeout.
    */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    printf("multiplexing: waiting in select() with a 1-second timeout\n");

    /* highest_fd + 1 is part of the select() API contract. */
    int rc = select(p[0] + 1, &rfds, NULL, NULL, &tv);
    if (rc < 0)
    {
        fprintf(stderr, "multiplexing: select failed: %s\n", strerror(errno));
    }
    else if (rc == 0)
    {
        printf("multiplexing: select() timed out\n");
    }
    else if (FD_ISSET(p[0], &rfds))
    {
        /*
            select() only tells us "this fd is readable now".
            We still need a real read() call to consume the bytes and inspect the data.
        */
        char buf[64];
        ssize_t n = read_retry(p[0], buf, sizeof(buf) - 1);
        if (n < 0)
        {
            fprintf(stderr, "multiplexing: read after select failed: %s\n", strerror(errno));
        }
        else
        {
            buf[n] = '\0';
            printf("multiplexing: select() reported readable data: \"%s\"\n", buf);
        }
    }

    /*
        The first read consumed the bytes written for the select() example.
        So we write a fresh message into the same pipe before demonstrating poll().
    */
    if (write_all(p[1], msg, strlen(msg)) == -1)
    {
        fprintf(stderr, "multiplexing: write before poll failed: %s\n", strerror(errno));
        close_checked(p[0], "multiplexing");
        close_checked(p[1], "multiplexing");
        return;
    }
    printf("multiplexing: wrote \"%s\" to the pipe before poll()\n", msg);

    /*
        poll() uses struct pollfd entries instead of bitmaps, so it avoids the highest-fd rule and reports events per descriptor.
        We ask poll() to watch p[0] for POLLIN, which means "there is data to read". The kernel writes the result into pfd.revents.
    */
    struct pollfd pfd;
    pfd.fd = p[0];
    pfd.events = POLLIN;
    pfd.revents = 0;
    printf("multiplexing: waiting in poll() with a 2-second timeout\n");

    rc = poll(&pfd, 1, 2000);
    if (rc < 0)
    {
        fprintf(stderr, "multiplexing: poll failed: %s\n", strerror(errno));
    }
    else if (rc == 0)
    {
        printf("multiplexing: poll() timed out\n");
    }
    else if (pfd.revents & POLLIN)
    {
        /*
            As with select(), readiness is just a notification. We still perform read() to pull the available bytes out of the pipe.
        */
        char buf[64];
        ssize_t n = read_retry(p[0], buf, sizeof(buf) - 1);
        if (n < 0)
        {
            fprintf(stderr, "multiplexing: read after poll failed: %s\n", strerror(errno));
        }
        else
        {
            buf[n] = '\0';
            printf("multiplexing: poll() reported readable data: \"%s\"\n", buf);
        }
    }

    /* Close both ends of the pipe now that the readiness demo is finished. */
    close_checked(p[0], "multiplexing");
    close_checked(p[1], "multiplexing");
}

/* Run each demo against small local files under data/ in the current working directory. */
int main(void)
{
    const char *test_file = "data/02-demo_file_io.txt";
    const char *direct_io_file = "data/02-demo_direct_io.bin";

    printf("Starting Linux file-I/O demonstrations.\n");
    if (ensure_data_dir() == -1)
        return 1;
    show_open_fds();
    printf("main: regular demo file = %s\n", test_file);
    printf("main: direct-I/O demo file = %s\n", direct_io_file);

    demo_basic_io(test_file);
    demo_sync(test_file);
    demo_position(test_file);
    demo_truncation(test_file);
    demo_direct_io(direct_io_file);
    demo_multiplexing();

    printf("\nAll file-I/O demonstrations completed.\n");
    return 0;
}
