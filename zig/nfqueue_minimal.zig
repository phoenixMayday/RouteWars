const std = @import("std");

const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfad: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg;
    _ = data;

    var id: c_uint = undefined;
    var payload: [*c]u8 = undefined;
    var payload_len: c_int = undefined;

    const packet_hdr = netfilter.nfq_get_msg_packet_hdr(nfad);
    if (packet_hdr == null) {
        return netfilter.NF_DROP;
    }
    id = packet_hdr.*.packet_id;

    payload_len = netfilter.nfq_get_payload(nfad, &payload);
    std.debug.print("Packet received (id: {}, length: {} bytes)\n", .{ id, payload_len });

    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

pub fn main() !void {
    //var allocator = std.heap.CAllocator{};

    var h: ?*netfilter.nfq_handle = undefined;
    var qh: ?*netfilter.nfq_q_handle = undefined;
    var fd: c_int = undefined;
    var buf: [4096]u8 = undefined;
    var rv: c_int = undefined;

    h = netfilter.nfq_open();
    if (h == null) {
        std.debug.print("Error during nfq_open()\n", .{});
        return error.NfqOpenFailed;
    }
    defer _ = netfilter.nfq_close(h);

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
    defer _ = netfilter.nfq_destroy_queue(qh); // Ensure the queue is destroyed on exit

    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        std.debug.print("Error during nfq_set_mode()\n", .{});
        return error.NfqSetModeFailed;
    }

    fd = netfilter.nfq_fd(h);

    while (true) {
        rv = @as(c_int, @intCast(std.c.recv(fd, &buf, buf.len, 0)));
        if (rv >= 0) {
            _ = netfilter.nfq_handle_packet(h, &buf, rv); // Handle the packet
        } else {
            std.debug.print("Error during recv()\n", .{});
            break;
        }
    }
}
