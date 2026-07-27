#!/bin/sh
set -eu

cd "$(dirname "$0")"

MODULE=koops
PREFIX=KOOPS_EVT
CAPTURE_DIR=../_captures
CAPTURE_FILE=$CAPTURE_DIR/modules-koops.txt
MARKER=KOOPS_CAPTURE_BEGIN_$$_$(date +%s)
loaded=no

capture_records()
{
	mkdir -p "$CAPTURE_DIR"
	dmesg | sed -n "/$MARKER/,\$p" | grep -F "$PREFIX" > "$CAPTURE_FILE" || :
}

cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$loaded" = yes ]; then
		rmmod "$MODULE" || :
	fi
	capture_records
	exit "$status"
}

trap cleanup EXIT HUP INT TERM

printf "<6>%s\n" "$MARKER" > /dev/kmsg

printf "== modinfo ==\n"
modinfo "./$MODULE.ko"

printf "\n== load %s ==\n" "$MODULE"
insmod "./$MODULE.ko"
loaded=yes

printf "\n== loaded modules ==\n"
grep "^$MODULE " /proc/modules

printf "\n== unload ==\n"
rmmod "$MODULE"
loaded=no

capture_records
trap - EXIT HUP INT TERM

printf "\nCaptured %s records in %s\n" "$(grep -c "$PREFIX" "$CAPTURE_FILE")" "$CAPTURE_FILE"
