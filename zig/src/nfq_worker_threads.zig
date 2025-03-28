const std = @import("std");

// Import C Netfilter libraries for access to nfqueue
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});
const logger = @import("logger.zig");

// Values we can change for testing
const TIMEOUT_NS = 1_000_000_000; // 1 second timeout
const NUM_WORKER_THREADS = 5;
var allocator = std.heap.page_allocator;

// nfq_handle represents a connection to the Netfilter queue subsystem
const QueueHandle = ?*netfilter.nfq_handle;

// nfq_q_handle represents a SPECIFIC queue in the Netfilter queue subsystem
const Queue = ?*netfilter.nfq_q_handle;

// Make a packet queue that can be safely accessed
const Packet = struct { payload: []u8, id: c_uint };
var packet_queue: std.ArrayList(Packet) = undefined; // dynamic array of packets waiting to be processed
var mutex = std.Thread.Mutex{}; // mutex to synchronise access to packet_queue
var cond = std.Thread.Condition{}; // will signal worker threads when new packets are available

// Thread pool
var thread_pool: std.ArrayList(std.Thread) = undefined; // dynamic array of worker threads
var shutdown = false; // signals worker threads to shutdown gracefully

// Function to be executed by each worker thread
fn worker() void {
    while (true) {
        // Safely access packet_queue and wait for incoming packets
        mutex.lock();

        while (packet_queue.items.len == 0 and !shutdown) {
            cond.timedWait(&mutex, TIMEOUT_NS) catch {
                // Timeout reached, check if we should shutdown
                if (shutdown) {
                    mutex.unlock();
                    return;
                }
                continue;
            };
        }

        if (shutdown and packet_queue.items.len == 0) {
            mutex.unlock();
            return;
        }

        // Take the next packet from the queue
        const packet = packet_queue.orderedRemove(0);
        mutex.unlock();

        // Process the packet
        logger.log("Processing packet (id: {}, length: {} bytes). First {} bytes: ", .{
            packet.id,
            packet.payload.len,
            @min(packet.payload.len, 16),
        });
        for (0..@min(packet.payload.len, 16)) |i| {
            logger.log("{x:0>2} ", .{packet.payload[i]});
        }
        logger.log("\n", .{});
        allocator.free(packet.payload);
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
        logger.log("Error: Failed to get packet header\n", .{});
        return netfilter.NF_DROP;
    }
    id = std.mem.bigToNative(u32, packet_hdr.*.packet_id);

    payload_len = netfilter.nfq_get_payload(nfad, &payload);

    if (payload_len >= 0) {
        logger.log("Packet received (id: {}, length: {} bytes)\n", .{ id, payload_len });

        // Copy payload to heap
        const payload_copy = allocator.alloc(u8, @intCast(payload_len)) catch {
            logger.log("Error: Failed to allocate memory for payload\n", .{});
            return netfilter.NF_DROP;
        };
        @memcpy(payload_copy, payload[0..@intCast(payload_len)]);

        // Add packet to queue
        mutex.lock();
        defer mutex.unlock();

        packet_queue.append(Packet{ .payload = payload_copy, .id = id }) catch {
            allocator.free(payload_copy);
            logger.log("Error: Failed to add packet to queue\n", .{});
            return netfilter.NF_DROP;
        };

        // Signal one worker thread
        cond.signal();
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
        logger.log("Error during nfq_open()\n", .{});
        return error.NfqOpenFailed;
    }

    defer _ = netfilter.nfq_close(h); // Discard the return value

    // Unbind then re-bind Netfilter queue to AF_INET
    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_unbind_pf()\n", .{});
        return error.NfqUnbindFailed;
    }
    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_bind_pf()\n", .{});
        return error.NfqBindFailed;
    }

    // Create new queue with the packet handling callback
    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        logger.log("Error during nfq_create_queue()\n", .{});
        return error.NfqCreateQueueFailed;
    }
    defer _ = netfilter.nfq_destroy_queue(qh);

    // Set queue mode to copy entire packet to user space
    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        logger.log("Error during nfq_set_mode()\n", .{});
        return error.NfqSetModeFailed;
    }

    // Get file descriptor for queue
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
        rv = @as(c_int, @intCast(std.c.recv(fd, &buf, buf.len, 0)));
        if (rv >= 0) {
            _ = netfilter.nfq_handle_packet(h, &buf, rv);
        } else {
            logger.log("Error during recv()\n", .{});
            break;
        }
    }
}
