#!/bin/bash
IMAGES="launch_bash_alpine launch_bash_ubuntu launch_java launch_js launch_python launch_pd"
RUNTIME="io.containerd.kata.v2"
# Force Kata to use the specific QEMU config we just edited
export KATA_CONF_FILE="/etc/kata-containers/configuration-qemu.toml"

RUNS=${1:-1}
PORT=9090
TIMEOUT=60
RESULTS_DIR="/home/ubuntu/shared_folder/benchmarks/results"
mkdir -p $RESULTS_DIR

OUTFILE="${RESULTS_DIR}/startup_qemu_ht_$(date +%s).csv"
echo "image,run,time_s" > $OUTFILE

echo ">>> Starting Kata Startup Benchmark (HyperTurtle QEMU)"
echo ">>> Config: $KATA_CONF_FILE"
echo ">>> Using Race-Condition Fix: sleep 0.5 before entrypoint"

for img in $IMAGES; do
    echo "=== $img ==="
    for r in $(seq 1 $RUNS); do
        name="${img}_run${r}"
        sudo docker rm -f $name > /dev/null 2>&1

        # START TIMER
        start=$(date +%s%N)

        # Launch with a small delay inside the container to let the L1 exporter 
        # map the PCI device and let the L1 kernel write the CR3.
        sudo docker run --rm -d -p $PORT:$PORT --runtime $RUNTIME \
            --entrypoint /bin/sh --name $name $img \
            -c "sleep 0.5 && /entrypoint.sh" > /dev/null 2>&1

        connected=false
        while [ $(( ($(date +%s%N) - start) / 1000000000 )) -lt $TIMEOUT ]; do
            if nc -z -w 1 localhost $PORT 2>/dev/null; then
                connected=true
                break
            fi
            sleep 0.05
        done

        end=$(date +%s%N)

        if [ "$connected" = true ]; then
            elapsed=$(echo "scale=3; ($end - $start) / 1000000000" | bc)
            echo "  run $r: ${elapsed}s"
            echo "$img,$r,$elapsed" >> $OUTFILE
        else
            echo "  run $r: TIMEOUT"
        fi

        sudo docker stop -t 1 $name > /dev/null 2>&1
    done
done
