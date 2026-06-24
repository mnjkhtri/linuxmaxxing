#!/bin/sh
set -eu

cd "$(dirname "$0")"

MODE=${1:-core}

mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys

case "$MODE" in
	core)
		MODULE_DIR=core
		MODULE=core_koops
		ARGS=
		PREFIX=KOOPS_CORE
		;;
	mm)
		MODULE_DIR=mm
		MODULE=mm_koops
		ARGS=
		PREFIX=KOOPS_MM
		;;
	*)
		printf 'usage: %s {core|mm}\n' "$0" >&2
		exit 2
		;;
esac

printf '== modinfo ==\n'
modinfo "./$MODULE_DIR/$MODULE.ko"

printf '\n== load %s ==\n' "$MODULE"
insmod "./$MODULE_DIR/$MODULE.ko" $ARGS
sleep 2

printf '\n== loaded modules ==\n'
grep "$MODULE" /proc/modules

printf '\n== unload ==\n'
rmmod "$MODULE"

printf '\n== dmesg ==\n'
dmesg | grep "$PREFIX" | tail -n 120
