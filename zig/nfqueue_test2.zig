const std = @import("std");

// Import C Netfilter libraries for access to nfqueue
// https://github.com/formorer/pkg-libnetfilter-queue/blob/master/src/libnetfilter_queue.c
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});

// Values we can change for testing
const BATCH_SIZE = 10;
const TIMEOUT_NS = 1_000_000_000; // 1 second timeout
const NUM_WORKER_THREADS = 3; // Can be adjusted to match system's capabilities
var allocator = std.heap.page_allocator;

// nfq_handle represents a connection to the Netfilter queue subsystem
// You'd use this handle for opening/closing opening a connection to the queue
const QueueHandle = ?*netfilter.nfq_handle;

// nfq_q_handle represents a SPECIFIC queue in the Netfilter queue subsystem
// You'd use this handle for determining how packets are handled
const Queue = ?*netfilter.nfq_q_handle;

// Make a packet queue that can be safely accessed
const Packet = struct { payload: []u8, id: c_uint };
var packet_queue: std.ArrayList(Packet) = undefined; // dynamic array of packets waiting to be processed
var mutex = std.Thread.Mutex{}; // mutex to synchronise access to packet_queue
var cond = std.Thread.Condition{}; // will signal worker threads when new packets are available

// Set up a thread pool instead of endlessly generating new threads!
var thread_pool: std.ArrayList(std.Thread) = undefined; // dynamic array of worker threads
var shutdown = false; // signals worker threads to shutdown gracefully

// Function to be executed by each worker thread
fn worker() void {
    while (true) {
        // Safely access packet_queue and wait for incoming packets
        mutex.lock();

        while (packet_queue.items.len == 0 and !shutdown) {
            cond.timedWait(&mutex, TIMEOUT_NS) catch {
                // Timeout reached, process whatever packets are available
                break;
            };
        }

        if (packet_queue.items.len == 0) {
            mutex.unlock();
            if (shutdown) { // Graceful shutdown
                break;
            } else { // Or skip iteration
                continue;
            }
        }
        if (shutdown and packet_queue.items.len == 0) { // graceful shutdown
            mutex.unlock();
            break;
        }

        // Take ownership of packets in queue and clear the queue (all in one convenient fucnction :] )
        const batch = packet_queue.toOwnedSlice() catch {
            mutex.unlock();
            std.debug.print("Error: Failed to take ownership of packet queue\n", .{});
            continue;
        };
        mutex.unlock();

        std.debug.print("Batch size: {}\n", .{batch.len});

        // Process packets in batch
        for (batch) |packet| {
            // Print the first few bytes of the payload for demonstration
            std.debug.print("Packet processed (id: {}, length: {} bytes). First {} bytes: ", .{
                packet.id,
                packet.payload.len,
                @min(packet.payload.len, 16),
            });
            for (0..@min(packet.payload.len, 16)) |i| {
                std.debug.print("{x:0>2} ", .{packet.payload[i]});
            }
            std.debug.print("\n", .{});
            allocator.free(packet.payload);
        }
        allocator.free(batch);
    }
}

// Function to handle the packets. Will be invoked when a packet is received by the queue
fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfad: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg; // Unused parameter
    _ = data; // Unused parameter

    // Packet info
    var id: c_uint = undefined;
    var payload: [*c]u8 = undefined;
    var payload_len: c_int = undefined;

    // Dereference the pointer to access the packet header
    const packet_hdr = netfilter.nfq_get_msg_packet_hdr(nfad);
    if (packet_hdr == null) {
        std.debug.print("Error: Failed to get packet header\n", .{});
        return netfilter.NF_DROP;
    }
    id = packet_hdr.*.packet_id; // Dereference the C pointer

    payload_len = netfilter.nfq_get_payload(nfad, &payload);

    if (payload_len >= 0) {
        std.debug.print("Packet received (id: {}, length: {} bytes)\n", .{ id, payload_len });

        // Copy payload to heap
        const payload_copy = allocator.alloc(u8, @intCast(payload_len)) catch {
            std.debug.print("Error: Failed to allocate memory for payload\n", .{});
            return netfilter.NF_DROP;
        };
        @memcpy(payload_copy, payload[0..@intCast(payload_len)]);

        // Add packet to queue
        mutex.lock();
        packet_queue.append(Packet{ .payload = payload_copy, .id = id }) catch {
            allocator.free(payload_copy);
            mutex.unlock();
            std.debug.print("Error: Failed to add packet to queue\n", .{});
            return netfilter.NF_DROP;
        };

        // Signal worker thread once batch size is reach
        if (packet_queue.items.len >= BATCH_SIZE) {
            cond.signal();
        }

        mutex.unlock();
    }

    // Re-inject the packet back into the kernel
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

pub fn main() !void {
    var h: QueueHandle = undefined; // queue subsystem handle
    var qh: Queue = undefined; // specific queue handle
    var fd: c_int = 0; // file descriptor for queue
    var buf: [4096]u8 = undefined; // packet buffer
    var rv: c_int = 0; // return value

    // Open the netfilter queue
    h = netfilter.nfq_open();
    if (h == null) {
        std.debug.print("Error during nfq_open()\n", .{});
        return error.NfqOpenFailed;
    }

    defer _ = netfilter.nfq_close(h); // Discard the return value

    // Unbind then re-bind Netfilter queue to AF_INET
    // AF_INET is the IPv4 protocol family, there's AF_INET6 and AF_UNIX for IPv6 and local comms
    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_unbind_pf()\n", .{});
        return error.NfqUnbindFailed;
    }
    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_bind_pf()\n", .{});
        return error.NfqBindFailed;
    }

    // Create new queue with the packet handling callback
    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        std.debug.print("Error during nfq_create_queue()\n", .{});
        return error.NfqCreateQueueFailed;
    }
    defer _ = netfilter.nfq_destroy_queue(qh);

    // Set queue mode to copy entire packet to user space
    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        std.debug.print("Error during nfq_set_mode()\n", .{});
        return error.NfqSetModeFailed;
    }

    // Get file descriptor for queue so we know where to read from
    fd = netfilter.nfq_fd(h);

    // Initialise packet_queue
    packet_queue = std.ArrayList(Packet).init(allocator);
    defer packet_queue.deinit();

    // Initialise thread pool
    thread_pool = std.ArrayList(std.Thread).init(allocator);
    defer {
        shutdown = true;
        cond.broadcast();
        for (thread_pool.items) |thread| {
            thread.join();
        }
        thread_pool.deinit();
    }

    for (0..NUM_WORKER_THREADS) |_| {
        const thread = try std.Thread.spawn(.{}, worker, .{});
        try thread_pool.append(thread);
    }

    while (true) {
        // Receive data from the queue
        // Cast the return value of std.c.recv to c_int
        rv = @as(c_int, @intCast(std.c.recv(fd, &buf, buf.len, 0)));
        if (rv >= 0) {
            _ = netfilter.nfq_handle_packet(h, &buf, rv); // Discard the return value
        } else {
            std.debug.print("Error during recv()\n", .{});
            break;
        }
    }
}
