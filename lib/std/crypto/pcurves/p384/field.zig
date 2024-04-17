const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("p384_64.zig"),
    .field_order = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    .field_bits = 384,
    .saturated_bits = 384,
    .encoded_length = 48,
});
