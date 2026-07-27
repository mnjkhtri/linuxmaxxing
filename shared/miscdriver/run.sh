#!/bin/sh
set -eu

cd "$(dirname "$0")"

MODULE=llkd_miscdrv
DEVICE=/dev/llkd_miscdrv

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys

printf '== modinfo ==\n'
modinfo "./$MODULE.ko"

if grep -q "^$MODULE " /proc/modules; then
	printf '\n== unload existing %s ==\n' "$MODULE"
	rmmod "$MODULE"
fi

printf '\n== load %s ==\n' "$MODULE"
insmod "./$MODULE.ko"
sleep 2

printf '\n== loaded module ==\n'
grep "^$MODULE " /proc/modules

printf '\n== device node ==\n'
ls -l "$DEVICE"

printf '\n== write test ==\n'
printf 'hello misc driver\n' > "$DEVICE"

printf '\n== read test ==\n'
dd if="$DEVICE" bs=64 count=1 2>/dev/null || true
printf '\n'

printf '\n== dmesg ==\n'
dmesg | grep "$MODULE:" | tail -n 120

printf '\n%s remains loaded; run `rmmod %s` to unload it.\n' "$MODULE" "$MODULE"
