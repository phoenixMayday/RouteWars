const std = @import("std");

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
