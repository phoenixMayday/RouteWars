#!/bin/bash

#ROUTER_EXECUTABLE="../zig/zig-out/bin/zig_router"
#ROUTER_EXECUTABLE="../go/nfq_go_router"

#ROUTER_EXECUTABLE="../rust/target/debug/nfq_rust_router"
#ROUTER_EXECUTABLE="../rust/target/debug/accept_all"
#ROUTER_EXECUTABLE="../rust/target/debug/dns_filter_noio"
#ROUTER_EXECUTABLE="../rust/target/debug/thread_everything"
#ROUTER_EXECUTABLE="../rust/target/debug/worker_threads"
ROUTER_EXECUTABLE="../rust/target/debug/dns_filter_worker_threads"

PACKET_TIMEOUT=0.1

ROUTER_OUTPUT="router_output.txt"
DNSPERF_OUTPUT="dnsperf_output.txt"
PERF_OUTPUT="perf_stat_output.txt"
PARSED_OUTPUT="parsed_output.txt"

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
sudo ip netns exec ns2 perf stat -p $ROUTER_PID -o $PERF_OUTPUT -e cycles,instructions,cache-references,cache-misses,branches,branch-misses,page-faults,context-switches,cpu-migrations,LLC-load-misses &

# Run dnsperf benchmark
echo "Starting dnsperf benchmark..."
sudo ip netns exec ns1 dnsperf -s 192.168.1.2 -d ./queries.txt -n 1000000 -t $PACKET_TIMEOUT -q 1000 > $DNSPERF_OUTPUT 2>&1

# Stop router implementation
echo "Stopping router implementation..."
sudo kill $ROUTER_PID

# Stop DNS server
echo "Stopping DNS server..."
sudo kill $DNS_SERVER_PID

# Give everything a sec to wrap up
sleep 2

# Parse output files
python3 ./extract_outputs.py "$PERF_OUTPUT" "$DNSPERF_OUTPUT" "$PARSED_OUTPUT"

echo "Benchmark completed. Output saved to:"
echo "- Router output: $ROUTER_OUTPUT"
echo "- DNSperf output: $DNSPERF_OUTPUT"
echo "- Perf stat output: $PERF_OUTPUT"
echo "- Parsed output: $PARSED_OUTPUT"
