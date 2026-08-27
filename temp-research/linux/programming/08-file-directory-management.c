#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/*
    Small Linux file and directory management demonstrations.

    The examples cover:
      - stat(), lstat(): inode metadata
      - mkdir(), opendir(), readdir(), closedir(), rmdir(): directories
      - link(), symlink(), unlink(): hard and soft links
*/

static void ensure_data_dir(void)
{
    (void)mkdir("data", 0755);
}

/*
    Demo 1: stat() reads inode metadata.

    stat() follows symlinks to the target; lstat() stops at the link itself.
*/
static void demo_stat(void)
{
    printf("\n------ 1. stat(): inode metadata ------\n");

    struct stat st;
    if (stat("/etc/hostname", &st) == -1)
    {
        fprintf(stderr, "stat: %s\n", strerror(errno));
        return;
    }

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&st.st_mtime));

    printf("stat: path   /etc/hostname\n");
    printf("stat: inode  %lu\n", (unsigned long)st.st_ino);
    printf("stat: size   %lld bytes\n", (long long)st.st_size);
    printf("stat: mode   %04o\n", (unsigned)(st.st_mode & 07777));
    printf("stat: nlink  %lu\n", (unsigned long)st.st_nlink);
    printf("stat: uid    %d  gid %d\n", (int)st.st_uid, (int)st.st_gid);
    printf("stat: mtime  %s\n", tbuf);
}

/*
    Demo 2: directory operations.

    mkdir() creates a directory. opendir/readdir yields each entry as a
    struct dirent with d_name and d_ino. rmdir() removes an empty directory.
*/
static void demo_directory(void)
{
    printf("\n------ 2. Directories: mkdir, readdir, rmdir ------\n");

    ensure_data_dir();
    const char *dir = "data/08-workdir";

    if (mkdir(dir, 0755) == -1 && errno != EEXIST)
    {
        fprintf(stderr, "directory: mkdir: %s\n", strerror(errno));
        return;
    }

    const char *files[] = {"data/08-workdir/alpha.txt", "data/08-workdir/beta.txt"};
    for (int i = 0; i < 2; ++i)
    {
        int fd = open(files[i], O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd != -1)
            close(fd);
    }

    DIR *dp = opendir(dir);
    if (!dp)
    {
        fprintf(stderr, "directory: opendir: %s\n", strerror(errno));
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL)
        printf("directory: ino=%-8lu  %s\n", (unsigned long)ent->d_ino, ent->d_name);
    closedir(dp);

    for (int i = 0; i < 2; ++i)
        unlink(files[i]);
    rmdir(dir);
}

/*
    Demo 3: hard links and symbolic links.

    link() creates a second directory entry pointing to the same inode — st_nlink increments to 2.
    symlink() creates a separate inode whose data is the target pathname.
    stat() follows the symlink;
    lstat() reads the symlink's own inode.
    unlink() removes a directory entry; the inode is freed only when both the link count and the open-descriptor count reach zero.
*/
static void demo_links(void)
{
    printf("\n------ 3. Links: link(), symlink(), lstat(), unlink() ------\n");

    ensure_data_dir();
    const char *target = "data/08-target.txt";
    const char *hard = "data/08-hard.txt";
    const char *soft = "data/08-soft.txt";

    int fd = open(target, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
    {
        fprintf(stderr, "links: open: %s\n", strerror(errno));
        return;
    }
    close(fd);

    struct stat st;

    /* step 1: target alone — nlink starts at 1 */
    stat(target, &st);
    printf("links: target created         inode=%-8lu  nlink=%lu\n",
           (unsigned long)st.st_ino, (unsigned long)st.st_nlink);

    /* step 2: hard link — same inode, nlink becomes 2 */
    if (link(target, hard) == -1)
        fprintf(stderr, "links: link: %s\n", strerror(errno));
    stat(target, &st);
    printf("links: after link()           inode=%-8lu  nlink=%lu  (nlink incremented)\n",
           (unsigned long)st.st_ino, (unsigned long)st.st_nlink);
    stat(hard, &st);
    printf("links: hardlink               inode=%-8lu  nlink=%lu  (same inode as target)\n",
           (unsigned long)st.st_ino, (unsigned long)st.st_nlink);

    /* step 3: symlink — its own inode, stores the target path as data */
    if (symlink("08-target.txt", soft) == -1)
        fprintf(stderr, "links: symlink: %s\n", strerror(errno));
    lstat(soft, &st);
    printf("links: symlink lstat()        inode=%-8lu  size=%lld bytes (stores path \"08-target.txt\")\n",
           (unsigned long)st.st_ino, (long long)st.st_size);
    stat(soft, &st);
    printf("links: symlink stat()         inode=%-8lu  (follows link, same inode as target)\n",
           (unsigned long)st.st_ino);

    unlink(target);
    unlink(hard);
    unlink(soft);
}

int main(void)
{
    printf("Starting file and directory management demonstrations.\n");

    demo_stat();
    demo_directory();
    demo_links();

    printf("\nAll file and directory management demonstrations completed.\n");
    return EXIT_SUCCESS;
}
