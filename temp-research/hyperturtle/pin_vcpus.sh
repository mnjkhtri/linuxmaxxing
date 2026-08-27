#!/bin/bash
# pin_vcpus_fixed.sh — Correct vCPU pinning for HyperTurtle L1
#
# Layout (20 online cores, SMT off):
#   Core 0:      Non-vCPU QEMU threads (main, IO, workers)
#   Cores 1-12:  vCPU threads, 1:1 pinned
#   Cores 13-19: Free (other system tasks)
#
# Note: Cores 1-9 are NUMA node 0, cores 10-12 are NUMA node 1.
#       This matches the paper's 12-vCPU config; cross-NUMA is accepted.

set -euo pipefail

QEMU_PID=$(pgrep -f "qemu-system.*ubuntu-l1" || true)
if [ -z "$QEMU_PID" ]; then
    echo "ERROR: No QEMU process found for ubuntu-l1"
    exit 1
fi

NUM_VCPUS=12
VCPU_START_CORE=1
HOUSEKEEPING_CORE=0

echo "=== QEMU PID: $QEMU_PID ==="
echo ""

# Get all TIDs sorted numerically
ALL_TIDS=($(ls /proc/$QEMU_PID/task/ | sort -n))
TOTAL=${#ALL_TIDS[@]}
echo "Total QEMU threads: $TOTAL"

# QEMU thread layout (sorted by TID creation order):
#   TID[0]  = main thread
#   TID[1]  = IO thread (or similar)
#   TID[2]  through TID[2+NUM_VCPUS-1] = vCPU threads
#   Everything else = workers, IO helpers, late-spawned
#
# We need at least 2 + NUM_VCPUS threads
MIN_THREADS=$((2 + NUM_VCPUS))
if [ "$TOTAL" -lt "$MIN_THREADS" ]; then
    echo "ERROR: Expected at least $MIN_THREADS threads, found $TOTAL"
    exit 1
fi

# Extract vCPU TIDs (indices 2 through 2+NUM_VCPUS-1)
VCPU_TIDS=()
for i in $(seq 2 $((2 + NUM_VCPUS - 1))); do
    VCPU_TIDS+=("${ALL_TIDS[$i]}")
done

# Everything NOT in VCPU_TIDS is housekeeping
declare -A VCPU_SET
for tid in "${VCPU_TIDS[@]}"; do
    VCPU_SET[$tid]=1
done

# Step 1: Pin ALL threads to housekeeping core first
echo ""
echo "--- Step 1: Pin ALL threads to core $HOUSEKEEPING_CORE ---"
for tid in "${ALL_TIDS[@]}"; do
    sudo taskset -p -c $HOUSEKEEPING_CORE $tid 2>/dev/null || true
done

# Step 2: Pin vCPU threads to their dedicated cores
echo ""
echo "--- Step 2: Pin vCPU threads to cores ${VCPU_START_CORE}-$((VCPU_START_CORE + NUM_VCPUS - 1)) ---"
core=$VCPU_START_CORE
for tid in "${VCPU_TIDS[@]}"; do
    sudo taskset -p -c $core $tid 2>/dev/null
    core=$((core + 1))
done

# Step 3: Re-scan for any threads spawned during pinning
echo ""
echo "--- Step 3: Catch late-spawned threads ---"
CURRENT_TIDS=($(ls /proc/$QEMU_PID/task/ | sort -n))
LATE_COUNT=0
for tid in "${CURRENT_TIDS[@]}"; do
    if [ -z "${VCPU_SET[$tid]+_}" ]; then
        # Not a vCPU thread — ensure it's on housekeeping core
        current_mask=$(taskset -p $tid 2>/dev/null | awk '{print $NF}')
        if [ "$current_mask" != "1" ]; then
            sudo taskset -p -c $HOUSEKEEPING_CORE $tid 2>/dev/null || true
            LATE_COUNT=$((LATE_COUNT + 1))
        fi
    fi
done
echo "Re-pinned $LATE_COUNT late/drifted threads to core $HOUSEKEEPING_CORE"

# Step 4: Verification
echo ""
echo "=== VERIFICATION ==="
echo ""
printf "%-8s %-6s %-10s %-6s %s\n" "TID" "ROLE" "AFFINITY" "PSR" "MASK"
echo "-----------------------------------------------"

CURRENT_TIDS=($(ls /proc/$QEMU_PID/task/ | sort -n))
ERRORS=0
vcpu_idx=0
for tid in "${CURRENT_TIDS[@]}"; do
    mask=$(taskset -p $tid 2>/dev/null | awk '{print $NF}')
    psr=$(awk '{print $39}' /proc/$QEMU_PID/task/$tid/stat 2>/dev/null)

    if [ -n "${VCPU_SET[$tid]+_}" ]; then
        expected_core=$((VCPU_START_CORE + vcpu_idx))
        expected_mask=$(printf "%x" $((1 << expected_core)))
        role="vCPU-$vcpu_idx"
        vcpu_idx=$((vcpu_idx + 1))
        if [ "$mask" != "$expected_mask" ]; then
            role="$role !!ERR"
            ERRORS=$((ERRORS + 1))
        fi
    else
        role="housekp"
        if [ "$mask" != "1" ]; then
            role="$role !!ERR"
            ERRORS=$((ERRORS + 1))
        fi
    fi

    printf "%-8s %-10s %-10s %-6s %s\n" "$tid" "$role" "core=$psr" "" "mask=0x$mask"
done

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "ALL THREADS PINNED CORRECTLY"
else
    echo "WARNING: $ERRORS threads have unexpected affinity!"
fi

echo ""
echo "Summary:"
echo "  Housekeeping (core $HOUSEKEEPING_CORE): $((${#CURRENT_TIDS[@]} - NUM_VCPUS)) threads"
echo "  vCPU (cores ${VCPU_START_CORE}-$((VCPU_START_CORE + NUM_VCPUS - 1))): $NUM_VCPUS threads, 1:1"
echo "  NUMA split: cores 1-9 on node 0, cores 10-12 on node 1"
