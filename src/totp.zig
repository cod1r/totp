const std = @import("std");
const sha3 = @import("sha3/src/sha3.zig");

fn HMAC_SHA3_256(key: []u8, text: []u8) ![]u8 {
    var key_used = key;
    var other_key = try sha3.SHA3_256(key);
    var key_ipad: [64]u8 = undefined;
    var key_opad: [64]u8 = undefined;
    var pad_idx: usize = 0;
    while (pad_idx < 64) : (pad_idx += 1) {
        key_ipad[pad_idx] = 0;
        key_opad[pad_idx] = 0;
    }
    if (key.len > 64) {
        for (other_key) |val, idx| {
            key_ipad[idx] = val;
            key_opad[idx] = val;
        }
    } else {
        for (key_used) |val, idx| {
            key_ipad[idx] = val;
            key_opad[idx] = val;
        }
    }
    for (key_ipad) |_, idx| {
        key_ipad[idx] ^= 0x36;
    }
    for (key_opad) |_, idx| {
        key_opad[idx] ^= 0x5C;
    }
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var alloc = gpa.allocator();

    var append_inner = std.ArrayList(u8).init(alloc);
    try append_inner.appendSlice(key_ipad[0..]);
    try append_inner.appendSlice(text);

    var first_hash = try sha3.SHA3_256(append_inner.items);

    var append_outer = std.ArrayList(u8).init(alloc);
    try append_outer.appendSlice(key_opad[0..]);
    try append_outer.appendSlice(first_hash);

    var last_hash = try sha3.SHA3_256(append_outer.items);
    return last_hash;
}

fn genHOTPVal(key: []u8, text: []u8) ![]u8 {
    var sha_value = try HMAC_SHA3_256(key, text);
    var fourbytesidx = sha_value[31] & 0x0F;
    var bin_code =
        (@intCast(u64, sha_value[fourbytesidx] & 0x7F) << 24) |
        (@intCast(u64, sha_value[fourbytesidx + 1] & 0xFF) << 16) |
        (@intCast(u64, sha_value[fourbytesidx + 2] & 0xFF) << 8) |
        (@intCast(u64, sha_value[fourbytesidx + 3] & 0xFF));
    var digits = bin_code % std.math.pow(u64, 10, 6);
    var digit_arr: [6]u8 = undefined;
    for (digit_arr) |_, idx| {
        digit_arr[5 - idx] = @intCast(u8, (digits % 10) + 48);
        digits /= 10;
    }
    return digit_arr[0..];
}

pub fn main() !void {
    const time_step_seconds: u64 = 30;
    const T0: u64 = 0;
    var T = std.time.milliTimestamp();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var alloc = gpa.allocator();

    var bytes = std.ArrayList(u8).init(alloc);
    var steps: u64 = @intCast(u64, @divFloor((T - T0), time_step_seconds * 1000));
    var i: u6 = 0;
    while (i <= 7) : (i += 1) {
        try bytes.append(@intCast(u8, (steps & (@intCast(u64, 255) << (8 * i))) >> (8 * i)));
    }
    var key: []const u8 = "jjj";
    var key_arr = std.ArrayList(u8).init(alloc);
    try key_arr.appendSlice(key);
    var out = try genHOTPVal(key_arr.items, bytes.items);
    std.debug.print("{s}\n", .{out});
}
