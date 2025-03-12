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

var blocklist: std.ArrayList([]const u8) = undefined;

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
        const dns_payload = transport_payload[@sizeOf(dns.udphdr)..];

        // Decode the QNAME
        var buffer: [256]u8 = undefined;
        const qname = dns.decodeQname(dns_payload[0..], &buffer) catch |err| {
            std.debug.print("Error decoding QNAME: {}\n", .{err});
            return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
        };

        std.debug.print("UDP DNS Packet handled (ID: {}), Domain: {s}\n", .{ id, qname });

        // check if domain is in blocklist
        for (blocklist.items) |domain| {
            if (std.mem.eql(u8, qname, domain)) {
                std.debug.print("Domain {s} is blocked. Dropping packet.\n", .{qname});
                return netfilter.NF_DROP;
            }
        }
    }
    // TCP DNS
    else if (ip_header.ip_p == netinet.IPPROTO_TCP) {
        // Most DNS traffic is UDP so we won't implement this for now.
        std.debug.print("TCP Packet handled (ID: {})\n", .{id});
    }

    // Accept all packets
    return netfilter.nfq_set_verdict(queue, id, netfilter.NF_ACCEPT, 0, null);
}

fn loadBlocklist(allocator: std.mem.Allocator, file_path: []const u8) !std.ArrayList([]const u8) {
    var list = std.ArrayList([]const u8).init(allocator);
    const file = try std.fs.cwd().openFile(file_path, .{});
    defer file.close();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var line_buffer: [256]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&line_buffer, '\n')) |line| {
        // skip any comments or empty lines
        if (line.len == 0 or line[0] == '#') continue;

        const domain = std.mem.trim(u8, line, " \r\n"); // trim whitespace

        try list.append(try allocator.dupe(u8, domain));
    }

    return list;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // command line args
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: {s} <blocklist_file>\n", .{args[0]});
        std.process.exit(1);
    }

    // load blocklist
    blocklist = try loadBlocklist(allocator, args[1]);
    defer {
        for (blocklist.items) |domain| {
            allocator.free(domain);
        }
        blocklist.deinit();
    }

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
