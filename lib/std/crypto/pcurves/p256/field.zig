const std = @import("std");
const common = @import("../common.zig");

const Field = common.Field;

pub const Fe = Field(.{
    .fiat = @import("p256_64.zig"),
    .field_order = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    .field_bits = 256,
    .saturated_bits = 256,
    .encoded_length = 32,
});
