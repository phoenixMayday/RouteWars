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
const logger = @import("logger.zig");

const build_options = @import("build_options");

var prng = std.Random.DefaultPrng.init(0);

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

var packet_counter: u32 = 0;

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

    // Get the packet payload
    var payload: [*c]u8 = undefined;
    var payload_len: c_int = 0;
    payload_len = netfilter.nfq_get_payload(nfa, &payload);

    if (payload_len < 0) {
        logger.log("Error: Failed to get packet payload\n", .{});
        return netfilter.NF_DROP;
    }

    // Check the IP protocol
    const ip_header: *const dns.ip = @ptrCast(@alignCast(payload));
    const ip_header_len = (ip_header.ip_vhl & 0x0F) << 2; //ip_header.ip_hl << 2;
    const transport_payload: []u8 = payload[ip_header_len..@intCast(payload_len)];

    // UDP DNS
    if (ip_header.ip_p == netinet.IPPROTO_UDP) {
        // Calculate whether to ignore this packet based on ignore_dns percentage
        const ignore_dns = build_options.ignore_dns;
        const should_ignore = prng.random().intRangeLessThan(u8, 0, 100) < ignore_dns;
        packet_counter += 1;

        if (!should_ignore) {
            const dns_payload = transport_payload[@sizeOf(dns.udphdr)..];

            // Decode the QNAME
            var buffer: [256]u8 = undefined;
            const qname = dns.decodeQname(dns_payload[0..], &buffer) catch |err| {
                logger.log("Error decoding QNAME: {}\n", .{err});
                return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
            };

            logger.log("UDP DNS packet handled (ID: {}), Domain: {s}\n", .{ id, qname });
        } else {
            logger.log("UDP DNS packet handled as data packet (ID: {}).\n", .{id});
        }
    }
    // TCP DNS
    else if (ip_header.ip_p == netinet.IPPROTO_TCP) {
        // Most DNS traffic is UDP so we won't implement this for now.
        logger.log("TCP packet handled (ID: {}).\n", .{id});
    } else {
        logger.log("Data packet handled (ID: {}).\n", .{id});
    }

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
