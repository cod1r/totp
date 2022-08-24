const std = @import("std");

fn HMAC_SHA1_256(key: []u8, text: []u8) ![]u8 {
    var key_used = key;
    var sha1zig1 = std.crypto.hash.Sha1.init(.{});
    sha1zig1.update(key);
    var other_key: [20]u8 = undefined;
    sha1zig1.final(&other_key);
    //
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
    var sha1zig2 = std.crypto.hash.Sha1.init(.{});
    sha1zig2.update(key_ipad[0..]);
    sha1zig2.update(text);
    var first_hash: [20]u8 = undefined;
    sha1zig2.final(&first_hash);

    var sha1zig3 = std.crypto.hash.Sha1.init(.{});
    sha1zig3.update(key_opad[0..]);
    sha1zig3.update(first_hash[0..]);
    var last_hash: [20]u8 = undefined;
    sha1zig3.final(&last_hash);

    return last_hash[0..];
}

fn genHOTPVal(key: []u8, text: []u8, digit_len: usize) ![]u8 {
    var sha_value = try HMAC_SHA1_256(key, text);
    var fourbytesidx = sha_value[19] & 0x0F;
    var bin_code =
        (@intCast(u64, sha_value[fourbytesidx] & 0x7F) << 24) |
        (@intCast(u64, sha_value[fourbytesidx + 1] & 0xFF) << 16) |
        (@intCast(u64, sha_value[fourbytesidx + 2] & 0xFF) << 8) |
        (@intCast(u64, sha_value[fourbytesidx + 3] & 0xFF));
    var digits = bin_code % std.math.pow(u64, 10, digit_len);

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var alloc = gpa.allocator();
    var digit_arr = std.ArrayList(u8).init(alloc);
    try digit_arr.appendNTimes(0, digit_len);

    for (digit_arr.items) |_, idx| {
        digit_arr.items[digit_len - 1 - idx] = @intCast(u8, (digits % 10) + 48);
        digits /= 10;
    }
    return digit_arr.items;
}

fn genTOTPval(key: []const u8, digit_len: usize) !void {
    const time_step_seconds: u64 = 30;
    const T0: u64 = 0;
    var T = std.time.milliTimestamp();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var alloc = gpa.allocator();

    var bytes = std.ArrayList(u8).init(alloc);
    var steps: u64 = @intCast(u64, @divFloor((T - T0), time_step_seconds * 1000));
    var i: u6 = 8;
    while (i > 0) : (i -= 1) {
        try bytes.append(@intCast(u8, (steps & (@intCast(u64, 255) << (8 * (i - 1)))) >> (8 * (i - 1))));
    }
    var key_arr = std.ArrayList(u8).init(alloc);
    try key_arr.appendSlice(key);
    var out = try genHOTPVal(key_arr.items, bytes.items, digit_len);
    std.debug.print("{s}\n", .{out});
}

pub fn main() !void {
    var key = "";
    try genTOTPval(key, 6);
}
