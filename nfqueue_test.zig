const std = @import("std");

// Import C Netfilter libraries for access to nfqueue
// https://github.com/formorer/pkg-libnetfilter-queue/blob/master/src/libnetfilter_queue.c
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});

// nfq_handle represents a connection to the Netfilter queue subsystem
// You'd use this handle for opening/closing opening a connection to the queue
const QueueHandle = ?*netfilter.nfq_handle;

// nfq_q_handle represents a SPECIFIC queue in the Netfilter queue subsystem
// You'd use this handle for determining how packets are handled
const Queue = ?*netfilter.nfq_q_handle;

// IDEA: experiment with different Zig allocators to compare performance
var allocator = std.heap.page_allocator;

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

        // Spawn a new thread to handle the packet concurrently
        const handle_packet = struct {
            fn handle(payload_ptr: [*c]u8, len: c_int) void {
                // Simulate packet processing
                std.time.sleep(100000000); // 100ms delay

                // Print the first few bytes of the payload for demonstration
                const max_bytes_to_print = @as(usize, @intCast(@min(len, 16))); // Convert to usize
                std.debug.print("Packet processed (length: {} bytes). First {} bytes: ", .{ len, max_bytes_to_print });
                for (0..max_bytes_to_print) |i| {
                    std.debug.print("{x:0>2} ", .{payload_ptr[i]});
                }
                std.debug.print("\n", .{});
            }
        }.handle;

        // Spawn the thread without propagating errors
        if (std.Thread.spawn(.{}, handle_packet, .{ payload, payload_len })) |thread| {
            thread.detach();
        } else |_| { // Handle error
            std.debug.print("Error: Failed to spawn thread\n", .{});
        }
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
