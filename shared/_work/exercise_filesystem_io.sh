#!/bin/sh

set -eu

# Exercise procfs, sysfs, and tmpfs.
cat /proc/mounts >/dev/null
cat /sys/devices/system/cpu/online >/dev/null

mkdir -p /tmp/vfs-study
printf 'tmpfs data\n' > /tmp/vfs-study/tmp-file
cat /tmp/vfs-study/tmp-file >/dev/null

# Drive buffered writes and reads through the filesystem and block layers.
mkdir -p /root/block-z
dd if=/dev/zero of=/root/block-z/file bs=4K count=256 conv=fsync
dd if=/root/block-z/file of=/dev/null bs=4K
rm -f /root/block-z/file
sync
