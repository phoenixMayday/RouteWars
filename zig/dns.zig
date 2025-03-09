const std = @import("std");

// manually define netinet ip header as we cannot access the C one
pub const ip = extern struct {
    ip_vhl: u8,
    ip_tos: u8,
    ip_len: u16,
    ip_id: u16,
    ip_off: u16,
    ip_ttl: u8,
    ip_p: u8,
    ip_sum: u16,
    ip_src: u32,
    ip_dst: u32,
};

pub const udphdr = extern struct {
    uh_sport: u16, // Source port
    uh_dport: u16, // Destination port
    uh_ulen: u16, // UDP length
    uh_sum: u16, // UDP checksum
};

pub const tcphdr = extern struct {
    th_sport: u16, // Source port
    th_dport: u16, // Destination port
    th_seq: u32, // Sequence number
    th_ack: u32, // Acknowledgment number
    th_off: u8, // Data offset (4 bits) + reserved (4 bits)
    th_flags: u8, // Flags
    th_win: u16, // Window size
    th_sum: u16, // Checksum
    th_urp: u16, // Urgent pointer
};

// decode QNAME from DNS packet
pub fn decodeQname(packet: []const u8, offset: usize) !struct { name: []const u8, new_offset: usize } {
    var name = std.ArrayList(u8).init(std.heap.c_allocator);
    defer name.deinit();

    var current_offset = offset;
    var length = packet[current_offset];

    while (length != 0) {
        if (length & 0xC0 == 0xC0) {
            // Handle DNS name compression (pointer)
            const pointer_offset = ((@as(u16, length) & 0x3F) << 8) | @as(u16, packet[current_offset + 1]);
            const result = try decodeQname(packet, pointer_offset);
            try name.appendSlice(result.name);
            current_offset += 2;
            return .{ .name = name.items, .new_offset = current_offset };
        }

        // Append the label to the name
        try name.appendSlice(packet[current_offset + 1 .. current_offset + 1 + length]);
        try name.append('.');
        current_offset += 1 + length;
        length = packet[current_offset];
    }

    // Remove the trailing dot
    if (name.items.len > 0 and name.items[name.items.len - 1] == '.') {
        _ = name.pop();
    }

    return .{ .name = name.items, .new_offset = current_offset + 1 };
}
