const std = @import("std");
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

var allocator = std.heap.page_allocator;

fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfad: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg; // Unused parameter
    _ = data; // Unused parameter

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
        } else |_| {
            std.debug.print("Error: Failed to spawn thread\n", .{});
        }
    }

    // Re-inject the packet back into the kernel
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

pub fn main() !void {
    var h: QueueHandle = undefined;
    var qh: Queue = undefined;
    var fd: c_int = 0;
    var buf: [4096]u8 = undefined;
    var rv: c_int = 0;

    // Open the netfilter queue
    h = netfilter.nfq_open();
    if (h == null) {
        std.debug.print("Error during nfq_open()\n", .{});
        return error.NfqOpenFailed;
    }

    defer _ = netfilter.nfq_close(h); // Discard the return value

    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_unbind_pf()\n", .{});
        return error.NfqUnbindFailed;
    }

    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_bind_pf()\n", .{});
        return error.NfqBindFailed;
    }

    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        std.debug.print("Error during nfq_create_queue()\n", .{});
        return error.NfqCreateQueueFailed;
    }

    defer _ = netfilter.nfq_destroy_queue(qh); // Discard the return value

    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        std.debug.print("Error during nfq_set_mode()\n", .{});
        return error.NfqSetModeFailed;
    }

    fd = netfilter.nfq_fd(h);

    while (true) {
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
