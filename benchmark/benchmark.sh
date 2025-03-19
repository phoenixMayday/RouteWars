#!/bin/bash

ROUTER_EXECUTABLE="../zig/zig-out/bin/zig_router"

ROUTER_OUTPUT="router_output.txt"
DNSPERF_OUTPUT="dnsperf_output.txt"
PERF_OUTPUT="perf_stat_output.txt"
MEMORY_USAGE_LOG="ps_memory_output.txt"

# Start DNS server in background
echo "Starting DNS server..."
sudo ip netns exec ns2 dnsmasq --conf-file=/etc/dnsmasq-ns2/dnsmasq.conf --no-daemon &
DNS_SERVER_PID=$!

# Give DNS server a sec to start
sleep 2

# Run the router implementation in background
echo "Starting router implementation..."
sudo ip netns exec ns2 $ROUTER_EXECUTABLE > $ROUTER_OUTPUT 2>&1 &
ROUTER_PID=$!

# Give router another sec to start
sleep 2

# Use perf to monitor the router process
echo "Starting perf stat to monitor the router..."
sudo ip netns exec ns2 perf stat -p $ROUTER_PID -o $PERF_OUTPUT &

# Record memory usage
echo "Starting memory usage monitoring..."
echo "Time Elapsed (s),Memory Usage (kB)" > $MEMORY_USAGE_LOG
START_TIME=$(date +%s)
while kill -0 $ROUTER_PID 2>/dev/null; do
    CURRENT_TIME=$(date +%s)
    ELAPSED_TIME=$((CURRENT_TIME - START_TIME))
    MEM_USAGE=$(sudo ip netns exec ns2 ps -o rss= -p $ROUTER_PID)
    echo "$ELAPSED_TIME,$MEM_USAGE" >> $MEMORY_USAGE_LOG
    sleep 1
done &

# Run dnsperf benchmark
echo "Starting dnsperf benchmark..."
sudo ip netns exec ns1 dnsperf -s 192.168.1.2 -d ./queries.txt -n 1000000 > $DNSPERF_OUTPUT 2>&1

# Stop router implementation
echo "Stopping router implementation..."
sudo kill $ROUTER_PID

# Stop DNS server
echo "Stopping DNS server..."
sudo kill $DNS_SERVER_PID

# Calculate average memory usage
AVG_MEM_USAGE=$(awk -F',' 'NR>1 {sum+=$2; count++} END {print sum/count}' $MEMORY_USAGE_LOG)
echo "Average memory usage of the router: $AVG_MEM_USAGE kB"

echo "Benchmark completed. Output saved to:"
echo "- Router output: $ROUTER_OUTPUT"
echo "- DNSperf output: $DNSPERF_OUTPUT"
echo "- Perf stat output: $PERF_OUTPUT"

