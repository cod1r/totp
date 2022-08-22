//! Code is converted from 
//! https://github.com/XKCP/XKCP/blob/master/Standalone/CompactFIPS202/Python/CompactFIPS202.py
const std = @import("std");
const A = [200]u8;
const w: usize = 64;
const b: usize = 1600;
const l: usize = 6;
const num_rounds: usize = 24;

const RC = [_]u64{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

fn ROT(n: u64, rn: usize) u64 {
    var ret: u128 = @intCast(u128, n) << 64;
    ret |= n;
    ret <<= @intCast(u7, rn % 64);
    return @intCast(u64, ret >> 64);
}

fn REV(n: u8) u8 {
    var ret: u8 = 0;
    var place: u8 = 1 << 7;
    var inc_amt: u3 = 0;
    while (true) {
        if ((n & place) > 0) {
            ret |= (@intCast(u8, 1) << inc_amt);
        }
        place >>= 1;
        if (inc_amt == 7) {
            break;
        }
        inc_amt += 1;
    }
    return ret;
}

fn KeccakF1600onLanes(lanes: *[5][5]u64) void {
    var round: usize = 0;
    while (round < num_rounds) {
        var C: [5]u64 = undefined;
        for (C) |_, idx| {
            C[idx] = lanes[idx][0] ^ lanes[idx][1] ^ lanes[idx][2] ^ lanes[idx][3] ^ lanes[idx][4];
        }

        var D: [5]u64 = undefined;
        for (D) |_, idx| {
            D[idx] = C[(idx + 4) % 5] ^ ROT(C[(idx + 1) % 5], 1);
        }

        {
            var x: usize = 0;
            while (x < 5) {
                var y: usize = 0;
                while (y < 5) {
                    lanes[x][y] ^= D[x];
                    y += 1;
                }
                x += 1;
            }
        }

        {
            var x: usize = 1;
            var y: usize = 0;
            var current = lanes[x][y];
            var t: usize = 0;
            while (t < num_rounds) {
                var temp = x;
                x = y;
                y = (2 * temp + 3 * y) % 5;
                var temp_current = current;
                current = lanes[x][y];
                lanes[x][y] = ROT(temp_current, (t + 1) * (t + 2) / 2);
                t += 1;
            }
        }

        {
            var T: [5]u64 = undefined;
            var y: usize = 0;
            while (y < 5) {
                {
                    var x: usize = 0;
                    while (x < 5) {
                        T[x] = lanes[x][y];
                        x += 1;
                    }
                }
                {
                    var x: usize = 0;
                    while (x < 5) {
                        lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5]);
                        x += 1;
                    }
                }
                y += 1;
            }
        }

        lanes[0][0] ^= RC[round];

        round += 1;
    }
}

fn KeccakF1600(state: *A) void {
    var lanes: [5][5]u64 = undefined;
    {
        var x: usize = 0;
        while (x < 5) {
            var y: usize = 0;
            while (y < 5) {
                var sum: u64 = 0;
                var start: usize = 8 * (x + 5 * y);
                var end: usize = 8 * (x + 5 * y) + 8;
                var shift_amt: u6 = 0;
                while (start < end) {
                    sum +=
                        (@intCast(u64, state[start]) << (shift_amt * 8));
                    start += 1;
                    shift_amt += 1;
                }
                lanes[x][y] = sum;
                y += 1;
            }
            x += 1;
        }
    }

    KeccakF1600onLanes(&lanes);

    {
        var x: usize = 0;
        while (x < 5) {
            var y: usize = 0;
            while (y < 5) {
                var start: usize = 8 * (x + 5 * y);
                var end: usize = 8 * (x + 5 * y) + 8;
                var shift_amt: u6 = 0;
                while (start < end) {
                    state[start] = @intCast(
                        u8,
                        (lanes[x][y] >> (shift_amt * 8)) & ((1 << 8) - 1),
                    );
                    start += 1;
                    shift_amt += 1;
                }
                y += 1;
            }
            x += 1;
        }
    }
}

pub fn keccak(rate: usize, in: []const u8, digest_len: usize, lastbyte: u8) ![]u8 {
    var state: A = undefined;
    for (state) |_, idx| {
        state[idx] = 0;
    }
    var blockSize: usize = 0;
    var inputOffset: usize = 0;
    while (inputOffset < in.len) {
        blockSize = std.math.min(in.len - inputOffset, rate / 8);
        var i: usize = 0;
        while (i < blockSize) {
            state[i] ^= in[i + inputOffset];
            i += 1;
        }
        inputOffset += blockSize;
        if (blockSize == rate / 8) {
            KeccakF1600(&state);
            blockSize = 0;
        }
    }
    state[blockSize] ^= lastbyte;
    if (((lastbyte & 0x80) != 0) and (blockSize == (rate / 8 - 1))) {
        KeccakF1600(&state);
    }
    state[rate / 8 - 1] ^= 0x80;
    KeccakF1600(&state);
    var outputByteLen = digest_len;
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    var alloc = gpa.allocator();
    var outputBytes = std.ArrayList(u8).init(alloc);
    while (outputByteLen > 0) {
        blockSize = std.math.min(outputByteLen, rate / 8);
        try outputBytes.appendSlice(state[0..blockSize]);
        outputByteLen -= blockSize;
        if (outputByteLen > 0) {
            KeccakF1600(&state);
        }
    }
    return outputBytes.items;
}

test "ROT" {
    var r1 = ROT(2, 63);
    var r2 = ROT(1 << 63, 64);
    var r3 = ROT(1, 1);
    try std.testing.expect(r1 == 1);
    try std.testing.expect(r2 == 1 << 63);
    try std.testing.expect(r3 == 2);
}

test "REV" {
    var r1 = REV(0x4F);
    try std.testing.expect(r1 == 242);
}

test "sha3 224" {
    const ans: []const u8 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 224, in, 224 / 8, 0x06);
    try std.testing.expect(out.len == 224 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}

test "sha3 256" {
    const ans: []const u8 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 256, in, 256 / 8, 0x06);
    try std.testing.expect(out.len == 256 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}

test "sha3 384" {
    const ans: []const u8 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 384, in, 384 / 8, 0x06);
    try std.testing.expect(out.len == 384 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}

test "sha3 512" {
    const ans: []const u8 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 512, in, 512 / 8, 0x06);
    try std.testing.expect(out.len == 512 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}

test "shake 128" {
    const ans: []const u8 = "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 128, in, 256 / 8, 0x1F);
    try std.testing.expect(out.len == 256 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}

test "shake 256" {
    const ans: []const u8 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
    const in: []const u8 = "";
    const out: []u8 = try keccak(b - 2 * 256, in, 512 / 8, 0x1F);
    try std.testing.expect(out.len == 512 / 8);
    var index: usize = 0;
    for (out) |val| {
        var first = val >> 4;
        var second = val & ((1 << 4) - 1);
        if (first < 10) {
            first += 48;
        } else {
            first = 97 + (first - 10);
        }
        if (second < 10) {
            second += 48;
        } else {
            second = 97 + (second - 10);
        }

        try std.testing.expect(first == ans[index]);
        try std.testing.expect(second == ans[index + 1]);
        index += 2;
    }
}
