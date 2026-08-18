#!/bin/sh
set -eu

cd "$(dirname "$0")"

# =============================================================================
# KAPI capture
#
# The module reports KAPI_EVT ... lines through pr_info to dmesg.
# run.sh stamps a private marker into /dev/kmsg, then loads the module.
# The module init emits the full study; its exit frees everything it allocated.
# run.sh unloads the module, then captures every KAPI_EVT record written after the marker.
# The shared report directory holds the capture for the frontend.
#
# One module lifetime per run:
#   marker -> insmod (init emits events) -> rmmod (exit frees) -> capture
# =============================================================================

MODULE=kapi
PREFIX=KAPI_EVT
REPORT_DIR=../_captures
REPORT_FILE=$REPORT_DIR/kapi-Report.txt
MARKER=LX_CAPTURE_BEGIN_$$_$(date +%s)
loaded=no

preflight()
{
	[ "$(id -u)" -eq 0 ] || {
		echo "kapi: must run as root (insmod/rmmod/dmesg)" >&2
		exit 1
	}
	[ -e "./$MODULE.ko" ] || {
		echo "kapi: missing $MODULE.ko; run make -C shared/kapi first" >&2
		exit 1
	}
	command -v modinfo >/dev/null 2>&1 || {
		echo "kapi: modinfo not available" >&2
		exit 1
	}
	[ -r /proc/modules ] || {
		echo "kapi: /proc/modules not readable" >&2
		exit 1
	}
	if ! dmesg >/dev/null 2>&1; then
		echo "kapi: dmesg is not readable" >&2
		exit 1
	fi
	mkdir -p "$REPORT_DIR"
}

# Capture every record written after the marker.
# A missing match is a valid empty result here; validation decides whether it is a successful capture.
capture_records()
{
	dmesg | sed -n "/$MARKER/,\$p" | grep -F "$PREFIX" > "$REPORT_FILE" || :
}

validate()
{
	if [ ! -s "$REPORT_FILE" ]; then
		echo "kapi: captured zero records; module emitted nothing" >&2
		return 1
	fi
	if ! grep -q "$PREFIX domain=module phase=lifecycle action=ready" "$REPORT_FILE"; then
		echo "kapi: module never reached ready (init failed?)" >&2
		return 1
	fi
	return 0
}

# Always leave a report behind, even on a failed run, so failures are debuggable.
cleanup()
{
	status=$?
	trap - EXIT HUP INT TERM
	if [ "$loaded" = yes ]; then
		rmmod "$MODULE" 2>/dev/null || :
	fi
	capture_records
	exit "$status"
}

trap cleanup EXIT HUP INT TERM

preflight

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

# Normal path: disarm the trap before capturing so cleanup does not run again.
trap - EXIT HUP INT TERM
capture_records

if ! validate; then
	echo "kapi: capture failed validation" >&2
	exit 1
fi

printf "\nCaptured %s records in %s\n" "$(grep -c "$PREFIX" "$REPORT_FILE")" "$REPORT_FILE"