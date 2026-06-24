#!/bin/sh
set -eu

cd "$(dirname "$0")"

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys

printf '== modinfo ==\n'
modinfo ./qedu.ko

if grep -q '^qedu ' /proc/modules; then
	printf '\n== unload existing qedu ==\n'
	rmmod qedu
fi

printf '\n== load qedu ==\n'
insmod ./qedu.ko
sleep 2

printf '\n== loaded module ==\n'
grep '^qedu ' /proc/modules

printf '\n== device binding ==\n'
lspci -nnk -d 1234:11e8 2>/dev/null || true

printf '\n== dmesg ==\n'
dmesg | grep 'qedu:' | tail -n 120

printf '\nqedu remains loaded; run `rmmod qedu` to unload it.\n'
