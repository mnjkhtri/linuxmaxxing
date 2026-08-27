#!/bin/bash

# Configuration
ITERATIONS=10
LOG_FILE="redis_stats.log"
DOCKER_RUNTIME="io.containerd.kata.v2"
REDIS_DATA="/home/ubuntu/shared_folder/redis_data"

# Check for mode argument
if [[ "$1" != "ON" && "$1" != "OFF" ]]; then
    echo "Usage: $0 [ON|OFF]"
    exit 1
fi

echo "===================================================="
echo "  FIGURE 11 BENCHMARK: REDIS 1GiB SNAPSHOT ($1)  "
echo "===================================================="
echo "Iterations: $ITERATIONS"
echo "" > $LOG_FILE

for i in $(seq 1 $ITERATIONS); do
    echo -n "Run $i/$ITERATIONS... "
    
    # We use a subshell to capture the 'time' output which goes to stderr
    # The 'real' time is extracted and converted to raw seconds
    RUN_TIME=$( { time sudo docker run --rm \
        --runtime $DOCKER_RUNTIME \
        -v $REDIS_DATA:/data \
        redis:alpine redis-server --dir /data --rdbchecksum no > /dev/null 2>&1 ; } 2>&1 \
        | grep real | awk '{print $2}' | sed 's/0m//' | sed 's/s//' )
    
    echo "$RUN_TIME" >> $LOG_FILE
    echo "Time: ${RUN_TIME}s"
done

# Calculate Statistics
AVG=$(awk '{ sum += $1 } END { if (NR > 0) printf "%.3f", sum / NR }' $LOG_FILE)
MIN=$(sort -n $LOG_FILE | head -n 1)
MAX=$(sort -n $LOG_FILE | tail -n 1)

echo ""
echo "----------------------------------------------------"
echo "FINAL STATISTICS (Mode: $1)"
echo "----------------------------------------------------"
echo "Average Launch Time: ${AVG}s"
echo "Min: ${MIN}s | Max: ${MAX}s"
echo "----------------------------------------------------"
