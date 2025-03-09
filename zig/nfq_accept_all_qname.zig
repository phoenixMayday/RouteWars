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
const dns = @import("dns.zig");

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
    const ip_header: *const dns.ip = @ptrCast(@alignCast(payload));
    const ip_header_len = (ip_header.ip_vhl & 0x0F) << 2; //ip_header.ip_hl << 2;
    const transport_payload: []u8 = payload[ip_header_len..@intCast(payload_len)];

    // UDP DNS
    if (ip_header.ip_p == netinet.IPPROTO_UDP) {
        //std.debug.print("UDP DNS Packet detected!\n", .{});
        const domain = handleUdpDns(transport_payload);
        if (domain) |d| {
            std.debug.print("UDP DNS Packet handled (ID: {}), Domain: {s}\n", .{ id, d });
        }
    }
    // TCP DNS
    else if (ip_header.ip_p == netinet.IPPROTO_TCP) {
        //std.debug.print("TCP DNS Packet detected!\n", .{});
        const domain = handleTcpDns(transport_payload);
        if (domain) |d| {
            std.debug.print("2TCP DNS Packet handled (ID: {}), Domain: {s}\n", .{ id, d });
        }
    }

    // Accept all packets
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

// Function to handle UDP DNS packets
pub fn handleUdpDns(payload: []const u8) ?[]const u8 {
    const dns_payload = payload[@sizeOf(dns.udphdr)..];

    // Decode the QNAME
    const qname_result = dns.decodeQname(dns_payload, 12) catch {
        std.debug.print("Error: Failed to decode QNAME (UDP)\n", .{});
        return null;
    };

    return qname_result.name;
}

// Function to handle TCP DNS packets
pub fn handleTcpDns(payload: []const u8) ?[]const u8 {
    const tcp_header: *const dns.tcphdr = @ptrCast(@alignCast(payload));
    const tcp_header_len = (tcp_header.th_off >> 4) * 4; // extract 4-bit offset and multiply by 4 to get length in bytes

    //std.debug.print("TCP Header Length: {}\n", .{tcp_header_len});
    //std.debug.print("Payload Length: {}\n", .{payload.len});
    std.debug.print("Payload: {any}\n", .{payload});

    if (tcp_header_len > payload.len) {
        std.debug.print("Error: TCP header length exceeds payload length\n", .{});
        return null;
    }

    // Skip TCP header and 2-byte length field
    const dns_payload_with_length = payload[tcp_header_len..];
    if (dns_payload_with_length.len < 2) {
        std.debug.print("Error: DNS payload with length field is too short\n", .{});
        return null;
    }

    // Extract the DNS message length (first 2 bytes)
    const dns_payload = dns_payload_with_length[2..];
    //const dns_message_len = std.mem.bigToNative(u16, @as(*const u16, @as(*const u16, @alignCast(@ptrCast(dns_payload_with_length[0..2].ptr)))).*);
    //std.debug.print("DNS Message Length: {}\n", .{dns_message_len});
    //std.debug.print("DNS Payload Length: {}\n", .{dns_payload.len});

    if (dns_payload.len == 0) {
        std.debug.print("Error: DNS payload is empty\n", .{});
        return null;
    }

    // Decode the QNAME
    const qname_result = dns.decodeQname(dns_payload, 12) catch {
        std.debug.print("Error: Failed to decode QNAME (TCP)\n", .{});
        return null;
    };

    std.debug.print("TCP DNS Packet handled, Domain: {s}\n", .{qname_result.name});

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
