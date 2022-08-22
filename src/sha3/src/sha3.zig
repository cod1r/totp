const std = @import("std");
const keccak = @import("keccak.zig");

pub fn SHA3_256(inputBytes: []u8) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 256, inputBytes, 256/8, 0x06);
    return outputBytes;
}

pub fn SHA3_224(inputBytes: []u8) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 224, inputBytes, 224/8, 0x06);
    return outputBytes;
}

pub fn SHA3_384(inputBytes: []u8) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 384, inputBytes, 384/8, 0x06);
    return outputBytes;
}

pub fn SHA3_512(inputBytes: []u8) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 512, inputBytes, 512/8, 0x06);
    return outputBytes;
}

pub fn SHAKE_128(inputBytes: []u8, outputByteLen: usize) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 128, inputBytes, outputByteLen, 0x1F);
    return outputBytes;
}

pub fn SHAKE_256(inputBytes: []u8, outputByteLen: usize) ![]u8 {
    const outputBytes = try keccak.keccak(1600 - 2 * 256, inputBytes, outputByteLen, 0x1F);
    return outputBytes;
}
