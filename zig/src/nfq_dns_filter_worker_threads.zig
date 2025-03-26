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

const TIMEOUT_NS = 1_000_000_000; // 1 second timeout
const NUM_WORKER_THREADS = 5;
var allocator = std.heap.page_allocator;
var prng = std.Random.DefaultPrng.init(0);

const QueueHandle = ?*netfilter.nfq_handle;
const Queue = ?*netfilter.nfq_q_handle;

const blocklist = [_][]const u8{ "example.com", "malicious.com", "ads.example.org" };

const Packet = struct {
    payload: []u8,
    id: c_uint,
    queue: Queue,
};

var packet_queue: std.ArrayList(Packet) = undefined;
var mutex = std.Thread.Mutex{};
var cond = std.Thread.Condition{};
var thread_pool: std.ArrayList(std.Thread) = undefined;
var shutdown = false;

fn worker() void {
    while (true) {
        mutex.lock();
        defer mutex.unlock();

        while (packet_queue.items.len == 0 and !shutdown) {
            cond.timedWait(&mutex, TIMEOUT_NS) catch {
                // Timeout reached, check if we should shutdown
                if (shutdown) return;
                continue;
            };
        }

        if (shutdown and packet_queue.items.len == 0) { // graceful shutdown
            return;
        }

        // process packet (we unlock mutex during processing)
        const packet = packet_queue.orderedRemove(0);
        mutex.unlock();
        defer mutex.lock();
        processPacket(packet);
    }
}

// packet processing logic
fn processPacket(packet: Packet) void {
    defer allocator.free(packet.payload);

    const payload_len = packet.payload.len;
    const payload = packet.payload.ptr;

    // Check IP protocol
    const ip_header: *const dns.ip = @ptrCast(@alignCast(payload));
    const ip_header_len = (ip_header.ip_vhl & 0x0F) << 2;

    if (payload_len < ip_header_len) {
        logger.log("Invalid packet length (ID: {})\n", .{packet.id});
        _ = netfilter.nfq_set_verdict(packet.queue, packet.id, netfilter.NF_ACCEPT, 0, null);
        return;
    }

    const transport_payload = packet.payload[ip_header_len..];

    // UDP DNS
    if (ip_header.ip_p == netinet.IPPROTO_UDP) {
        const ignore_dns = build_options.ignore_dns;
        const should_ignore = prng.random().intRangeLessThan(u8, 0, 100) < ignore_dns;

        if (!should_ignore and transport_payload.len >= @sizeOf(dns.udphdr)) {
            const dns_payload = transport_payload[@sizeOf(dns.udphdr)..];

            // Decode the QNAME
            var buffer: [256]u8 = undefined;
            if (dns.decodeQname(dns_payload[0..], &buffer)) |qname| {
                logger.log("UDP DNS packet (ID: {}), Domain: {s}\n", .{ packet.id, qname });

                // Check if domain is in blocklist
                for (blocklist) |domain| {
                    if (std.mem.eql(u8, qname, domain)) {
                        logger.log("Blocking domain: {s}\n", .{qname});
                        _ = netfilter.nfq_set_verdict(packet.queue, packet.id, netfilter.NF_DROP, 0, null);
                        return;
                    }
                }
            } else |err| {
                logger.log("DNS decode error (ID: {}): {}\n", .{ packet.id, err });
            }
        }
    }
    // TCP DNS
    else if (ip_header.ip_p == netinet.IPPROTO_TCP) {
        logger.log("TCP packet (ID: {})\n", .{packet.id});
    }

    _ = netfilter.nfq_set_verdict(packet.queue, packet.id, netfilter.NF_ACCEPT, 0, null);
}

fn callback(queue: Queue, nfmsg: ?*netfilter.nfgenmsg, nfa: ?*netfilter.nfq_data, data: ?*anyopaque) callconv(.C) c_int {
    _ = nfmsg;
    _ = data;

    var id: c_uint = undefined;
    const packet_hdr = netfilter.nfq_get_msg_packet_hdr(nfa);

    if (packet_hdr == null) {
        logger.log("Error: Failed to get packet header\n", .{});
        return netfilter.NF_DROP;
    }
    id = std.mem.bigToNative(u32, packet_hdr.*.packet_id);

    // Get the packet payload
    var payload: [*c]u8 = undefined;
    const payload_len = netfilter.nfq_get_payload(nfa, &payload);

    if (payload_len <= 0) {
        logger.log("Error: Failed to get packet payload\n", .{});
        return netfilter.NF_DROP;
    }

    // Copy payload to heap
    const payload_copy = allocator.alloc(u8, @intCast(payload_len)) catch {
        logger.log("Error: Failed to allocate memory for payload\n", .{});
        return netfilter.NF_DROP;
    };
    @memcpy(payload_copy, payload[0..@intCast(payload_len)]);

    // Add packet to queue
    mutex.lock();
    defer mutex.unlock();

    packet_queue.append(Packet{
        .payload = payload_copy,
        .id = id,
        .queue = queue,
    }) catch {
        allocator.free(payload_copy);
        logger.log("Error: Failed to add packet to queue\n", .{});
        return netfilter.NF_DROP;
    };

    // Signal one worker thread
    cond.signal();

    // Return NF_QUEUE to indicate we're handling it asynchronously
    return netfilter.NF_QUEUE;
}

pub fn main() !void {
    var h: QueueHandle = undefined;
    var qh: Queue = undefined;
    var fd: c_int = undefined;
    var buf: [4096]u8 = undefined;
    var rv: c_int = undefined;

    // initialise packet queue
    packet_queue = std.ArrayList(Packet).init(allocator);
    defer packet_queue.deinit();

    // initialise thread pool
    thread_pool = std.ArrayList(std.Thread).init(allocator);
    defer {
        // cleanup
        shutdown = true;
        cond.broadcast();
        for (thread_pool.items) |thread| {
            thread.join();
        }
        thread_pool.deinit();
    }

    // create worker threads
    for (0..NUM_WORKER_THREADS) |_| {
        const thread = try std.Thread.spawn(.{}, worker, .{});
        try thread_pool.append(thread);
    }

    // open netfilter queue
    h = netfilter.nfq_open();
    if (h == null) {
        logger.log("Error during nfq_open()\n", .{});
        return error.NfqOpenFailed;
    }
    defer _ = netfilter.nfq_close(h);

    // bind to AF_INET
    if (netfilter.nfq_unbind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_unbind_pf()\n", .{});
        return error.NfqUnbindFailed;
    }
    if (netfilter.nfq_bind_pf(h, netfilter.AF_INET) < 0) {
        logger.log("Error during nfq_bind_pf()\n", .{});
        return error.NfqBindFailed;
    }

    // create queue with callback
    qh = netfilter.nfq_create_queue(h, 0, callback, null);
    if (qh == null) {
        logger.log("Error during nfq_create_queue()\n", .{});
        return error.NfqCreateQueueFailed;
    }
    defer _ = netfilter.nfq_destroy_queue(qh);

    // set copy mode
    if (netfilter.nfq_set_mode(qh, netfilter.NFQNL_COPY_PACKET, 0xffff) < 0) {
        logger.log("Error during nfq_set_mode()\n", .{});
        return error.NfqSetModeFailed;
    }

    // get queue file descriptor
    fd = netfilter.nfq_fd(h);

    while (true) {
        rv = @as(c_int, @intCast(std.c.recv(fd, &buf, buf.len, 0)));
        if (rv >= 0) {
            _ = netfilter.nfq_handle_packet(h, &buf, rv);
        } else {
            logger.log("Error during recv()\n", .{});
            break;
        }
    }
}
