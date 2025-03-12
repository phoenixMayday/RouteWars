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
pub fn decodeQname(payload: []const u8, buffer: []u8) ![]const u8 {
    var index: usize = 12; // skip the DNS header (12 bytes)
    var bufferIndex: usize = 0;

    while (true) {
        if (index >= payload.len) {
            return error.InvalidPacket; // prevent out-of-bounds access
        }

        const length = payload[index]; // length of each label, e.g., [3]www[7]example[3]com[0]
        if (length == 0) break; // end of QNAME

        // check if adding the length and '.' would exceed buffer size
        if (bufferIndex + length + 1 > buffer.len) {
            return error.BufferOverflow;
        }

        if (bufferIndex > 0) {
            buffer[bufferIndex] = '.';
            bufferIndex += 1;
        }
        index += 1;

        for (0..length) |_| {
            buffer[bufferIndex] = payload[index];
            bufferIndex += 1;
            index += 1;
        }
    }
    return buffer[0..bufferIndex];
}
