const std = @import("std");
const netfilter = @cImport({
    @cInclude("libnetfilter_queue/libnetfilter_queue.h");
    @cInclude("linux/netfilter.h");
});
const netinet = @cImport({
    @cInclude("netinet/ip.h");
    @cInclude("netinet/tcp.h");
    @cInclude("netinet/udp.h");
});
const qname = @import("qname.zig");

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfa: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg;
    _ = data;

    var id: u32 = 0;
    const packet_hdr = netfilter.nfq_get_msg_packet_hdr(nfa);

    if (packet_hdr == null) {
        std.debug.print("Error: Failed to get packet header\n", .{});
        return netfilter.NF_DROP;
    }
    id = std.mem.bigToNative(u32, packet_hdr.*.packet_id);

    // Get the packet payload
    var payload: [*c]u8 = undefined;
    var payload_len: c_int = 0;
    payload_len = netfilter.nfq_get_payload(nfa, &payload);

    if (payload_len < 0) {
        std.debug.print("Error: Failed to get packet payload\n", .{});
        return netfilter.NF_DROP;
    }

    // Check the IP protocol
    const ip_header: *const netinet.ip = @ptrCast(payload);
    const ip_header_len = ip_header.ip_hl << 2;
    const transport_payload: usize = payload[ip_header_len..@intCast(payload_len)];

    // UDP DNS
    if (ip_header.ip_p == netinet.IPPROTO_UDP) {
        const domain = handleUdpDns(transport_payload);
        if (domain) |d| {
            std.debug.print("UDP DNS Packet handled (ID: {}), Domain: {s}\n", .{ id, d });
        }
    }
    // TCP DNS
    else if (ip_header.ip_p == netinet.IPPROTO_TCP) {
        const domain = handleTcpDns(transport_payload);
        if (domain) |d| {
            std.debug.print("TCP DNS Packet handled (ID: {}), Domain: {s}\n", .{ id, d });
        }
    }

    // Accept all packets
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

// Function to handle UDP DNS packets
pub fn handleUdpDns(payload: []const u8) ?[]const u8 {
    const dns_payload = payload[@sizeOf(std.c.udphdr)..];

    // Decode the QNAME
    const qname_result = qname.decodeQname(dns_payload, 12) catch {
        std.debug.print("Error: Failed to decode QNAME (UDP)\n", .{});
        return null;
    };

    return qname_result.name;
}

// Function to handle TCP DNS packets
pub fn handleTcpDns(payload: []const u8) ?[]const u8 {
    const tcp_header: *const std.c.tcphdr = @ptrCast(payload);
    const tcp_header_len = tcp_header.th_off << 2;
    const dns_payload = payload[tcp_header_len + 2 ..]; // Skip TCP header and 2-byte length field

    // Decode the QNAME
    const qname_result = qname.decodeQname(dns_payload, 12) catch {
        std.debug.print("Error: Failed to decode QNAME (TCP)\n", .{});
        return null;
    };

    return qname_result.name;
}

pub fn main() !void {
    var h: ?*netfilter.nfq_handle = undefined;
    var qh: ?*netfilter.nfq_q_handle = undefined;
    var fd: c_int = undefined;
    var buf: [4096]u8 = undefined;
    var rv: c_int = undefined;

    h = netfilter.nfq_open();
    if (h == null) {
        std.debug.print("Error during nfq_open()\n", .{});
        std.process.exit(1);
    }
    defer _ = netfilter.nfq_close(h);

    // Unbind existing nf_queue handler for AF_INET (if any)
    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_unbind_pf()\n", .{});
        std.process.exit(1);
    }

    // Bind nfnetlink_queue as the handler for AF_INET
    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        std.debug.print("Error during nfq_bind_pf()\n", .{});
        std.process.exit(1);
    }

    // Create a new queue handle
    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        std.debug.print("Error during nfq_create_queue()\n", .{});
        std.process.exit(1);
    }
    defer _ = netfilter.nfq_destroy_queue(qh);

    // Set the mode to copy packet data to userspace
    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        std.debug.print("Error during nfq_set_mode()\n", .{});
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
            std.debug.print("Error during recv()\n", .{});
            break;
        }
    }
}
