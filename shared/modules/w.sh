#!/bin/sh
set -eu

cd "$(dirname "$0")"

MODE=combined

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys

MODULE_DIR=.
MODULE=koops
PREFIXES="KOOPS_CORE|KOOPS_MM"

printf '== modinfo ==\n'
modinfo "./$MODULE.ko"

printf '\n== load %s ==\n' "$MODULE"
insmod "./$MODULE_DIR/$MODULE.ko"
sleep 2

printf '\n== loaded modules ==\n'
grep "$MODULE" /proc/modules

printf '\n== unload ==\n'
rmmod "$MODULE"

printf '\n== dmesg ==\n'
dmesg | grep -E "$PREFIXES" | tail -n 160
