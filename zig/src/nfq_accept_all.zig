const std = @import("std");
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});
const logger = @import("logger.zig");

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfa: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg;
    _ = data;

    var id: u32 = 0;
    const packet_hdr = netfilter.nfq_get_msg_packet_hdr(nfa);

    if (packet_hdr == null) {
        logger.log("Error: Failed to get packet header\n", .{});
        return netfilter.NF_DROP;
    }
    id = std.mem.bigToNative(u32, packet_hdr.*.packet_id);

    // Print a message when packet is being handled
    logger.log("Packet handled (ID: {})\n", .{id});

    // Accept all packets
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

pub fn main() !void {
    var h: ?*netfilter.nfq_handle = undefined;
    var qh: ?*netfilter.nfq_q_handle = undefined;
    var fd: c_int = undefined;
    var buf: [4096]u8 = undefined;
    var rv: c_int = undefined;

    h = netfilter.nfq_open();
    if (h == null) {
        logger.log("Error during nfq_open()\n", .{});
        std.process.exit(1);
    }
    defer _ = netfilter.nfq_close(h);

    // Unbind existing nf_queue handler for AF_INET (if any)
    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_unbind_pf()\n", .{});
        std.process.exit(1);
    }

    // Bind nfnetlink_queue as the handler for AF_INET
    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_bind_pf()\n", .{});
        std.process.exit(1);
    }

    // Create a new queue handle
    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        logger.log("Error during nfq_create_queue()\n", .{});
        std.process.exit(1);
    }
    defer _ = netfilter.nfq_destroy_queue(qh);

    // Set the mode to copy packet data to userspace
    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        logger.log("Error during nfq_set_mode()\n", .{});
        std.process.exit(1);
    }

    // Get the file descriptor associated with the queue
    fd = netfilter.nfq_fd(h);

    // Main loop to process packets
    while (true) {
        rv = @as(c_int, @intCast(std.c.recv(fd, &buf, buf.len, 0)));
        if (rv >= 0) {
            // Handle the packet
            _ = netfilter.nfq_handle_packet(h, &buf, rv);
        } else {
            logger.log("Error during recv()\n", .{});
            break;
        }
    }
}
