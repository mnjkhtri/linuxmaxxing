#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>     /* errno for syscall and stdio failures; EEXIST for mkdir() when the directory already exists */
#include <fcntl.h>     /* open() and descriptor flags such as O_WRONLY, O_CREAT, and O_TRUNC */
#include <pthread.h>   /* pthread_create(), pthread_join(); used to demonstrate stream locking across threads */
#include <stdio.h>     /* FILE, fopen(), fdopen(), fclose(), stdio buffered I/O, and stream state/query functions */
#include <stdlib.h>    /* general utilities; kept for standard library completeness in the example */
#include <string.h>    /* strlen() for byte counts and strerror() for readable error messages */
#include <sys/stat.h>  /* mkdir() declaration plus file mode bits such as 0755 and 0644 */
#include <sys/types.h> /* common system data types used by POSIX interfaces */
#include <time.h>      /* nanosleep(); used to make the stream-locking demo timing easier to observe */
#include <unistd.h>    /* close(), fsync(), fileno(), and other POSIX descriptor-oriented interfaces */

/*
    Small Linux buffered-I/O demonstrations built around stdio streams.

    The examples cover:
      - fopen(), fdopen(), fclose()
      - fgetc(), ungetc(), fputc(), fgets(), fputs()
      - fread(), fwrite()
      - fseek(), rewind(), ftell(), fgetpos(), fsetpos()
      - feof(), ferror(), clearerr()
      - fileno(), fflush(), fsync()
      - setvbuf() with _IOFBF, _IOLBF, _IONBF
      - flockfile(), ftrylockfile(), funlockfile(), *_unlocked()

    stdio adds a user-space buffer on top of the kernel file descriptor.
    That reduces syscall frequency for small reads and writes,
    but it also means stream state and kernel descriptor state can diverge until flushed.

    Stdio lives above the VFS and inode layer:
    the pathname still resolves to the same underlying file object, but stdio adds one more buffer in user space.
*/

struct record
{
    int id;
    double value;
    char name[16];
};

struct thread_args
{
    FILE *stream;
    const char *label;
};

static int ensure_data_dir(void)
{
    if (mkdir("data", 0755) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "main: mkdir(\"data\") failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int fclose_checked(FILE *stream, const char *label)
{
    if (fclose(stream) == EOF)
    {
        fprintf(stderr, "%s: fclose failed: %s\n", label, strerror(errno));
        return -1;
    }
    return 0;
}

static void print_stream_flags(FILE *stream, const char *label)
{
    printf("%s: feof=%d ferror=%d\n", label, feof(stream) != 0, ferror(stream) != 0);
}

/*
    Demo 1: stream creation and access modes.

    a+ keeps the stream readable, but every write still goes to EOF even if we seek elsewhere first.

    fopen() still ends in the same open-file path as open();
    the difference is that stdio returns a stream object that manages buffering and stream state for us.
*/
static void demo_open_modes(const char *filename)
{
    printf("\n--- 1. Stream setup: fopen(), access modes, append semantics ---\n");
    printf("open_modes: target file = %s\n", filename);

    FILE *stream = fopen(filename, "w");
    if (stream == NULL)
    {
        fprintf(stderr, "open_modes: fopen(\"w\") failed: %s\n", strerror(errno));
        return;
    }

    if (fputs("first line\n", stream) == EOF || fputs("second line\n", stream) == EOF)
    {
        fprintf(stderr, "open_modes: initial writes failed: %s\n", strerror(errno));
        fclose_checked(stream, "open_modes(w)");
        return;
    }

    if (fclose_checked(stream, "open_modes(w)") == -1)
        return;
    printf("open_modes: created the file with mode \"w\"\n");

    stream = fopen(filename, "a+");
    if (stream == NULL)
    {
        fprintf(stderr, "open_modes: fopen(\"a+\") failed: %s\n", strerror(errno));
        return;
    }

    if (fseek(stream, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "open_modes: fseek failed: %s\n", strerror(errno));
        fclose_checked(stream, "open_modes(a+)");
        return;
    }
    printf("open_modes: fseek() moved to the start, but mode \"a+\" still appends writes at EOF\n");

    if (fputs("appended from a+\n", stream) == EOF)
    {
        fprintf(stderr, "open_modes: append write failed: %s\n", strerror(errno));
        fclose_checked(stream, "open_modes(a+)");
        return;
    }

    if (fflush(stream) == EOF)
    {
        fprintf(stderr, "open_modes: fflush failed: %s\n", strerror(errno));
        fclose_checked(stream, "open_modes(a+)");
        return;
    }

    if (fseek(stream, 0, SEEK_SET) != 0)
    {
        fprintf(stderr, "open_modes: rewind via fseek failed: %s\n", strerror(errno));
        fclose_checked(stream, "open_modes(a+)");
        return;
    }

    printf("open_modes: file contents after the append write:\n");
    char line[128];
    while (fgets(line, sizeof(line), stream) != NULL)
        printf("  %s", line);

    if (ferror(stream))
        fprintf(stderr, "open_modes: fgets failed: %s\n", strerror(errno));

    fclose_checked(stream, "open_modes(a+)");
}

/*
    Demo 2: character-oriented interfaces.

    fgetc() returns int so EOF and valid byte values can be distinguished.
    ungetc() pushes a byte back so the next read sees it again.

    This is still byte-oriented I/O underneath.
    The character-focused API is a stdio convenience layer over the same file bytes.
*/
static void demo_character_io(const char *filename)
{
    printf("\n--- 2. Character I/O: fgetc(), ungetc(), fputc() ---\n");
    printf("char_io: target file = %s\n", filename);

    FILE *stream = fopen(filename, "w");
    if (stream == NULL)
    {
        fprintf(stderr, "char_io: fopen for write failed: %s\n", strerror(errno));
        return;
    }

    const char *header = "HEADER";
    for (size_t i = 0; header[i] != '\0'; ++i)
    {
        if (fputc(header[i], stream) == EOF)
        {
            fprintf(stderr, "char_io: fputc failed: %s\n", strerror(errno));
            fclose_checked(stream, "char_io(write)");
            return;
        }
    }
    if (fputc('\n', stream) == EOF)
    {
        fprintf(stderr, "char_io: trailing newline write failed: %s\n", strerror(errno));
        fclose_checked(stream, "char_io(write)");
        return;
    }

    if (fclose_checked(stream, "char_io(write)") == -1)
        return;

    stream = fopen(filename, "r");
    if (stream == NULL)
    {
        fprintf(stderr, "char_io: fopen for read failed: %s\n", strerror(errno));
        return;
    }

    int ch = fgetc(stream);
    if (ch == EOF)
    {
        fprintf(stderr, "char_io: fgetc failed before data was read\n");
        fclose_checked(stream, "char_io(read)");
        return;
    }
    printf("char_io: first byte from fgetc() = '%c'\n", ch);

    if (ungetc(ch, stream) == EOF)
    {
        fprintf(stderr, "char_io: ungetc failed: %s\n", strerror(errno));
        fclose_checked(stream, "char_io(read)");
        return;
    }
    printf("char_io: ungetc('%c') pushed the byte back onto the stream\n", ch);

    printf("char_io: remaining bytes from repeated fgetc(): ");
    while ((ch = fgetc(stream)) != EOF)
        putchar(ch);
    if (ferror(stream))
    {
        fprintf(stderr, "char_io: repeated fgetc failed: %s\n", strerror(errno));
        fclose_checked(stream, "char_io(read)");
        return;
    }
    if (feof(stream))
        printf("char_io: reached EOF after character-by-character reads\n");

    fclose_checked(stream, "char_io(read)");
}

/*
    Demo 3: binary I/O.

    fread() and fwrite() move fixed-size objects.
    The objects in memory must already obey the platform's alignment rules before you pass them around.

    The file stores raw bytes, not C types.
    fread()/fwrite() simply copy object representations between memory and the byte stream managed by the kernel.
*/
static void demo_binary_io(const char *filename)
{
    printf("\n--- 3. Binary I/O: fwrite(), fread() on records ---\n");
    printf("binary_io: target file = %s\n", filename);

    struct record out[] = {
        {1, 3.14159, "pi"},
        {2, 2.71828, "e"},
        {3, 1.61803, "phi"},
    };

    FILE *stream = fopen(filename, "wb");
    if (stream == NULL)
    {
        fprintf(stderr, "binary_io: fopen(\"wb\") failed: %s\n", strerror(errno));
        return;
    }

    size_t written = fwrite(out, sizeof(out[0]), sizeof(out) / sizeof(out[0]), stream);
    if (written != sizeof(out) / sizeof(out[0]))
    {
        fprintf(stderr, "binary_io: fwrite wrote %zu/%zu records\n",
                written, sizeof(out) / sizeof(out[0]));
        fclose_checked(stream, "binary_io(write)");
        return;
    }
    printf("binary_io: wrote %zu records, %zu bytes each\n", written, sizeof(out[0]));

    if (fclose_checked(stream, "binary_io(write)") == -1)
        return;

    stream = fopen(filename, "rb");
    if (stream == NULL)
    {
        fprintf(stderr, "binary_io: fopen(\"rb\") failed: %s\n", strerror(errno));
        return;
    }

    struct record in[3];
    size_t read_count = fread(in, sizeof(in[0]), 3, stream);
    if (read_count != 3)
    {
        fprintf(stderr, "binary_io: fread read %zu/3 records\n", read_count);
        fclose_checked(stream, "binary_io(read)");
        return;
    }

    for (size_t i = 0; i < read_count; ++i)
    {
        printf("binary_io: record %zu: id=%d value=%.5f name=%s\n",
               i, in[i].id, in[i].value, in[i].name);
    }

    fclose_checked(stream, "binary_io(read)");
}

/*
    Demo 4: stream positioning and status flags.

    fseek() clears EOF and discards any pushed-back bytes.
    clearerr() lets later operations continue after EOF or error state was observed.

    Stdio keeps its own logical cursor and status flags in user space, separate from
    the underlying inode metadata and separate from any one-shot read()/write() call.
*/
static void demo_position_and_state(const char *filename)
{
    printf("\n--- 4. Position and state: fseek(), rewind(), ftell(), fgetpos(), fsetpos(), feof(), clearerr() ---\n");
    printf("position: target file = %s\n", filename);

    FILE *stream = fopen(filename, "r");
    if (stream == NULL)
    {
        fprintf(stderr, "position: fopen failed: %s\n", strerror(errno));
        return;
    }

    char line[128];
    fpos_t saved;

    if (fgets(line, sizeof(line), stream) == NULL)
    {
        fprintf(stderr, "position: initial fgets failed\n");
        fclose_checked(stream, "position");
        return;
    }
    printf("position: first line: %s", line);

    long after_first = ftell(stream);
    if (after_first < 0)
    {
        fprintf(stderr, "position: ftell failed: %s\n", strerror(errno));
        fclose_checked(stream, "position");
        return;
    }
    printf("position: ftell after first line = %ld\n", after_first);

    if (fgetpos(stream, &saved) != 0)
    {
        fprintf(stderr, "position: fgetpos failed: %s\n", strerror(errno));
        fclose_checked(stream, "position");
        return;
    }

    if (fgets(line, sizeof(line), stream) == NULL)
    {
        fprintf(stderr, "position: second fgets failed\n");
        fclose_checked(stream, "position");
        return;
    }
    printf("position: second line: %s", line);

    if (fsetpos(stream, &saved) != 0)
    {
        fprintf(stderr, "position: fsetpos failed: %s\n", strerror(errno));
        fclose_checked(stream, "position");
        return;
    }

    if (fgets(line, sizeof(line), stream) == NULL)
    {
        fprintf(stderr, "position: reread after fsetpos failed\n");
        fclose_checked(stream, "position");
        return;
    }
    printf("position: line after fsetpos(): %s", line);

    rewind(stream);
    printf("position: rewind() returned to the start and cleared the status flags\n");
    print_stream_flags(stream, "position after rewind");

    while (fgets(line, sizeof(line), stream) != NULL)
        ;

    if (!feof(stream))
    {
        fprintf(stderr, "position: expected EOF after reading to the end\n");
        fclose_checked(stream, "position");
        return;
    }
    print_stream_flags(stream, "position at EOF");

    clearerr(stream);
    print_stream_flags(stream, "position after clearerr");

    if (fseek(stream, 0, SEEK_END) != 0)
    {
        fprintf(stderr, "position: fseek(SEEK_END) failed: %s\n", strerror(errno));
        fclose_checked(stream, "position");
        return;
    }

    long size = ftell(stream);
    if (size < 0)
    {
        fprintf(stderr, "position: ftell at end failed: %s\n", strerror(errno));
        fclose_checked(stream, "position");
        return;
    }
    printf("position: size from ftell() at SEEK_END = %ld bytes\n", size);

    fclose_checked(stream, "position");
}

/*
    Demo 5: descriptor bridging with fdopen(), fileno(), fflush(), fsync().

    fflush() moves bytes from the stdio buffer into the kernel.
    fsync() then asks the kernel to push that dirty file data to stable storage.

    This is the key boundary in buffered I/O: user-space buffering first, then
    the kernel page-cache and storage path below it.
*/
static void demo_descriptor_bridge(const char *filename)
{
    printf("\n--- 5. Descriptor bridging: fdopen(), fileno(), fflush(), fsync() ---\n");
    printf("descriptor_bridge: target file = %s\n", filename);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "descriptor_bridge: open failed: %s\n", strerror(errno));
        return;
    }
    printf("descriptor_bridge: opened raw descriptor %d\n", fd);

    FILE *stream = fdopen(fd, "w");
    if (stream == NULL)
    {
        fprintf(stderr, "descriptor_bridge: fdopen failed: %s\n", strerror(errno));
        close(fd);
        return;
    }

    if (fputs("buffered bytes staged in user space\n", stream) == EOF)
    {
        fprintf(stderr, "descriptor_bridge: fputs failed: %s\n", strerror(errno));
        fclose_checked(stream, "descriptor_bridge");
        return;
    }
    printf("descriptor_bridge: fileno(stream) = %d\n", fileno(stream));
    printf("descriptor_bridge: flush or seek the stream before mixing it with raw write() or lseek()\n");

    if (fflush(stream) == EOF)
    {
        fprintf(stderr, "descriptor_bridge: fflush failed: %s\n", strerror(errno));
        fclose_checked(stream, "descriptor_bridge");
        return;
    }
    printf("descriptor_bridge: fflush() moved the stdio buffer into the kernel\n");

    if (fsync(fileno(stream)) == -1)
    {
        fprintf(stderr, "descriptor_bridge: fsync failed: %s\n", strerror(errno));
        fclose_checked(stream, "descriptor_bridge");
        return;
    }
    printf("descriptor_bridge: fsync() requested durable writeback for the descriptor\n");

    fclose_checked(stream, "descriptor_bridge");
}

/*
    Demo 6: buffer policy control.

    setvbuf() must run before any data operation on that stream.
    The selected mode changes when stdio hands buffered data to the kernel,
    not when the kernel commits data to storage.

    So these modes control stdio's user buffer, not the VFS/page-cache layer below it.
*/
static void demo_buffer_modes(const char *block_file,
                              const char *line_file,
                              const char *none_file)
{
    printf("\n--- 6. Buffer modes: setvbuf(), _IOFBF, _IOLBF, _IONBF ---\n");

    char block_buf[BUFSIZ];
    FILE *block_stream = fopen(block_file, "w");
    if (block_stream == NULL)
    {
        fprintf(stderr, "buffer_modes: fopen(%s) failed: %s\n", block_file, strerror(errno));
        return;
    }
    if (setvbuf(block_stream, block_buf, _IOFBF, sizeof(block_buf)) != 0)
    {
        fprintf(stderr, "buffer_modes: setvbuf(_IOFBF) failed\n");
        fclose_checked(block_stream, "buffer_modes(block)");
        return;
    }
    printf("buffer_modes: %s uses block buffering with a %zu-byte user buffer\n",
           block_file, sizeof(block_buf));
    if (fputs("block-buffered writes are typically flushed when the buffer fills or when fflush()/fclose() runs\n",
              block_stream) == EOF)
    {
        fprintf(stderr, "buffer_modes: block write failed: %s\n", strerror(errno));
        fclose_checked(block_stream, "buffer_modes(block)");
        return;
    }
    fclose_checked(block_stream, "buffer_modes(block)");

    char line_buf[BUFSIZ];
    FILE *line_stream = fopen(line_file, "w");
    if (line_stream == NULL)
    {
        fprintf(stderr, "buffer_modes: fopen(%s) failed: %s\n", line_file, strerror(errno));
        return;
    }
    if (setvbuf(line_stream, line_buf, _IOLBF, sizeof(line_buf)) != 0)
    {
        fprintf(stderr, "buffer_modes: setvbuf(_IOLBF) failed\n");
        fclose_checked(line_stream, "buffer_modes(line)");
        return;
    }
    printf("buffer_modes: %s uses line buffering; each newline triggers a user-space flush\n",
           line_file);
    if (fputs("line one flushes on newline\nline two also flushes on newline\n", line_stream) == EOF)
    {
        fprintf(stderr, "buffer_modes: line write failed: %s\n", strerror(errno));
        fclose_checked(line_stream, "buffer_modes(line)");
        return;
    }
    fclose_checked(line_stream, "buffer_modes(line)");

    FILE *none_stream = fopen(none_file, "w");
    if (none_stream == NULL)
    {
        fprintf(stderr, "buffer_modes: fopen(%s) failed: %s\n", none_file, strerror(errno));
        return;
    }
    if (setvbuf(none_stream, NULL, _IONBF, 0) != 0)
    {
        fprintf(stderr, "buffer_modes: setvbuf(_IONBF) failed\n");
        fclose_checked(none_stream, "buffer_modes(none)");
        return;
    }
    printf("buffer_modes: %s uses unbuffered I/O; each stdio call goes to the kernel immediately\n",
           none_file);
    if (fputs("unbuffered stream example\n", none_stream) == EOF)
    {
        fprintf(stderr, "buffer_modes: unbuffered write failed: %s\n", strerror(errno));
        fclose_checked(none_stream, "buffer_modes(none)");
        return;
    }
    fclose_checked(none_stream, "buffer_modes(none)");
}

static void *locked_writer(void *arg)
{
    struct thread_args *ctx = arg;
    const char *suffix = " wrote this line while holding the stream lock\n";
    const struct timespec pause = {0, 20 * 1000 * 1000};

    flockfile(ctx->stream);
    for (int i = 0; i < 3; ++i)
    {
        fwrite_unlocked(ctx->label, 1, strlen(ctx->label), ctx->stream);
        fwrite_unlocked(suffix, 1, strlen(suffix), ctx->stream);
        nanosleep(&pause, NULL);
    }
    funlockfile(ctx->stream);

    return NULL;
}

/*
    Demo 7: stream locking.

    stdio already locks internally per call.
    Manual locking becomes useful when a larger region must be kept together across multiple stdio operations.

    The thread safety here is about the user-space stream object. It is different
    from kernel-level readiness calls like select(), poll(), or epoll().
*/
static void demo_stream_locking(const char *filename)
{
    printf("\n--- 7. Thread safety: flockfile(), ftrylockfile(), funlockfile(), *_unlocked() ---\n");
    printf("stream_locking: target file = %s\n", filename);

    FILE *stream = fopen(filename, "w+");
    if (stream == NULL)
    {
        fprintf(stderr, "stream_locking: fopen failed: %s\n", strerror(errno));
        return;
    }

    pthread_t thread;
    struct thread_args args = {stream, "worker"};

    int rc = pthread_create(&thread, NULL, locked_writer, &args);
    if (rc != 0)
    {
        fprintf(stderr, "stream_locking: pthread_create failed: %s\n", strerror(rc));
        fclose_checked(stream, "stream_locking");
        return;
    }

    const struct timespec pause = {0, 5 * 1000 * 1000};
    nanosleep(&pause, NULL);
    rc = ftrylockfile(stream);
    if (rc != 0)
    {
        printf("stream_locking: ftrylockfile() saw that another thread already owns the stream\n");
    }
    else
    {
        printf("stream_locking: ftrylockfile() acquired the stream immediately\n");
        funlockfile(stream);
    }

    rc = pthread_join(thread, NULL);
    if (rc != 0)
    {
        fprintf(stderr, "stream_locking: pthread_join failed: %s\n", strerror(rc));
        fclose_checked(stream, "stream_locking");
        return;
    }

    if (fflush(stream) == EOF)
    {
        fprintf(stderr, "stream_locking: fflush failed: %s\n", strerror(errno));
        fclose_checked(stream, "stream_locking");
        return;
    }

    rewind(stream);
    char line[128];
    while (fgets(line, sizeof(line), stream) != NULL)
        printf("stream_locking: %s", line);

    fclose_checked(stream, "stream_locking");
}

int main(void)
{
    const char *text_file = "data/03-demo_buffered_text.txt";
    const char *binary_file = "data/03-demo_buffered_records.bin";
    const char *fd_file = "data/03-demo_buffered_fd_bridge.txt";
    const char *block_file = "data/03-demo_block_buffered.txt";
    const char *line_file = "data/03-demo_line_buffered.txt";
    const char *none_file = "data/03-demo_unbuffered.txt";
    const char *thread_file = "data/03-demo_stream_locking.txt";

    printf("Starting buffered stdio demonstrations.\n");
    if (ensure_data_dir() == -1)
        return 1;

    demo_open_modes(text_file);
    demo_character_io(text_file);
    demo_binary_io(binary_file);
    demo_position_and_state(text_file);
    demo_descriptor_bridge(fd_file);
    demo_buffer_modes(block_file, line_file, none_file);
    demo_stream_locking(thread_file);

    printf("\nAll buffered-I/O demonstrations completed.\n");
    return 0;
}
