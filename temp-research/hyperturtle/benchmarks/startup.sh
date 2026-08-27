#!/bin/bash
IMAGES="launch_bash_alpine launch_bash_ubuntu launch_java launch_js launch_python launch_pd"
RUNTIME="io.containerd.kata.v2"
RUNS=${1:-1}
PORT=9090
TIMEOUT=60
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="/home/ubuntu/shared_folder/benchmarks/results"
mkdir -p $RESULTS_DIR

# Detect if hyperupcall is active
HT_STATUS="unknown"
if pgrep -f ept_fault.guest > /dev/null 2>&1; then
    HT_STATUS="ht_on"
else
    HT_STATUS="ht_off"
fi

OUTFILE="${RESULTS_DIR}/startup_${HT_STATUS}_${TIMESTAMP}.csv"

echo "image,run,time_s" > $OUTFILE

if [ "$HT_STATUS" = "ht_on" ]; then
    echo ">>> ept_fault.guest IS running — HyperTurtle ON"
else
    echo ">>> ept_fault.guest NOT running — HyperTurtle OFF (baseline)"
fi
echo "Saving results to $OUTFILE"
echo "Images: $IMAGES"
echo "Runs per image: $RUNS"
echo "Timeout per run: ${TIMEOUT}s"
echo ""

for img in $IMAGES; do
    echo "=== $img ==="

    # Restart containerd before each image to clear stale state
    # Removed daemon restart to prevent orphaning shims
    sleep 3

    for r in $(seq 1 $RUNS); do
        name="${img}_run${r}"

        # Clean up any leftover container with same name
        sudo docker stop -t 2 $name > /dev/null 2>&1 && sudo docker rm $name > /dev/null 2>&1
        sleep 1

        start=$(date +%s%N)
        sudo docker run --rm -d -p $PORT:$PORT --runtime $RUNTIME --name $name $img > /dev/null 2>&1

        # Poll until port responds, with timeout
        elapsed_check=0
        connected=false
        while [ $elapsed_check -lt $TIMEOUT ]; do
            if nc -z -w 1 localhost $PORT 2>/dev/null; then
                connected=true
                break
            fi
            sleep 0.05
            elapsed_check=$(( ($(date +%s%N) - start) / 1000000000 ))
        done

        end=$(date +%s%N)

        if [ "$connected" = true ]; then
            elapsed=$(echo "scale=3; ($end - $start) / 1000000000" | bc)
            echo "  run $r: ${elapsed}s"
            echo "$img,$r,$elapsed" >> $OUTFILE
        else
            echo "  run $r: TIMEOUT (${TIMEOUT}s)"
            echo "$img,$r,TIMEOUT" >> $OUTFILE
        fi

        # Force cleanup
        sudo docker stop -t 2 $name > /dev/null 2>&1 && sudo docker rm $name > /dev/null 2>&1
        sleep 2

        # Report zombie count
        zombies=$(ps aux | grep cloud-hyp | grep defunct | wc -l)
        if [ $zombies -gt 0 ]; then
            echo "  [warning: $zombies zombie cloud-hypervisor processes]"
        fi
    done
done

echo ""
echo "Done. Results in $OUTFILE"
echo "Final zombie count: $(ps aux | grep cloud-hyp | grep defunct | wc -l)"
