# Experiment 1 (OLD): [`nfq_thread_everything.zig`](src/nfq_thread_everything.zig)

As Zig is interoperable with C, we can use libnetfilter_queue C library to interface with the NFQUEUE that we set up with iptables.

### How it works:
- Opens a connection to Netfilter (`nfq_open()`).
- Creates a queue with `nfq_create_queue(h, 0, callback, null);` 
	- This doesn't actually create a new queue, but rather attaches to queue 0 (matching the iptables setup).
- Reads packets from the queue (`nfq_fd(h)`) and processes them in the `callback` function.
- Reinjects the packet into the kernel (`nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null)`).

In this first test, the only "processing" we're doing is spawning a new thread and printing the first 16 bytes of each packet. 

Can build executable by running
```sh
zig build-exe nfq_thread_everything.zig -lnetfilter_queue -lc
```
in the `zig/` directory.
### Results:
*TODO: Write this section after proper analysis has been done with profiling software instead of positing. For now, let's make assumptions based off of what we observed:*

An end user device can successfully access the internet through the router, and the packets are indeed printed on the screen. However, in less than a minute, the device stops being able to access the internet and nothing more is printed by the program. Since we're spawning a new thread (an OS-level thread too, not a lightweight one) for each packet, the Pi is probably getting overloaded and freezing up.

# Experiment 2 (OLD): [`nfq_worker_threads.zig`](src/nfq_worker_threads.zig)

Modifies the first experiment.
- Adds a pool of worker threads to handle the packets instead of spawning a new thread for each packet
- Processes packets in batches to reduce overhead

Can build executable by running
```sh
zig build-exe nfq_worker_threads.zig -lnetfilter_queue -lc
```
in the `zig/` directory.


# Experiment 3: [`nfq_accept_all_qname.zig`](src/nfq_accept_all_qname.zig)

In `zig/`:
```sh
sudo /opt/zig/zig build -Dmain-file=src/nfq_accept_all_qname.zig -Dignore-dns=0 -Dlog-mode=io-prints run
```

For running it in `ns2`:
```sh
sudo ip netns exec ns2 /opt/zig/zig build -Dmain-file=src/nfq_accept_all_qname.zig -Dignore-dns=0 -Dlog-mode=io-prints run
```