const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("secp256k1_64.zig"),
    .field_order = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});
