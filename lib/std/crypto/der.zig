//! Distinguised Encoding Rules
//!
//! A version of Basic Encoding Rules (BER) where there is exactly ONE way to
//! represent non-constructed elements. This is useful for cryptographic signatures.
//!
//! Defined in X.690 and X.691.
//!
//! Intro material:
//!     - https://en.wikipedia.org/wiki/X.690#DER_encoding
//!     - https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der
const std = @import("std");
const DateTime = std.DateTime;

const log = std.log.scoped(.der);

pub const Parser = struct {
    bytes: []const u8,
    index: u32 = 0,

    pub fn nextBool(self: *Parser) !bool {
        const ele = try self.next(.universal, false, .boolean);
        if (ele.slice.len() != 1) return error.InvalidBool;
        const val = self.view(ele)[0];
        if (val == 0x00) return false;
        if (val == 0xff) return true;

        return error.InvalidBool;
    }

    pub fn nextBitstring(self: *Parser) !BitString {
        const ele = try self.next(.universal, false, .bitstring);
        const bytes = self.view(ele);
        const right_padding = bytes[0];
        if (right_padding >= 8) return error.InvalidBitString;
        return .{
            .bytes = bytes[1..],
            .right_padding = @intCast(right_padding),
        };
    }

    pub fn nextDateTime(self: *Parser) !DateTime {
        const ele = try self.next(.universal, false, null);
        const bytes = self.view(ele);
        switch (ele.identifier.tag) {
            .utc_time => {
                // Example: "YYMMDD000000Z"
                if (bytes.len != 13)
                    return error.InvalidDateTime;
                if (bytes[12] != 'Z')
                    return error.InvalidDateTime;

                var date: DateTime.Date = undefined;
                date.year = try parseTimeDigits(bytes[0..2], 0, 99);
                date.year += if (date.year >= 50) 1900 else 2000;
                date.month = @enumFromInt(try parseTimeDigits(bytes[2..4], 1, 12));
                date.day = try parseTimeDigits(bytes[4..6], 1, 31);
                const time = try parseTime(bytes[6..12]);

                return DateTime{ .date = date, .time = time };
            },
            .generalized_time => {
                // Examples:
                // "19920622123421Z"
                // "19920722132100.3Z"
                if (bytes.len < 15)
                    return error.InvalidDateTime;

                var date: DateTime.Date = undefined;
                date.year = try parseYear4(bytes[0..4]);
                date.month = @enumFromInt(try parseTimeDigits(bytes[4..6], 1, 12));
                date.day = try parseTimeDigits(bytes[6..8], 1, 31);
                const time = try parseTime(bytes[8..14]);

                return DateTime{ .date = date, .time = time };
            },
            else => return error.InvalidDateTime,
        }
    }

    pub fn nextEnum(self: *Parser, comptime Enum: type) !Enum {
        const ele = try self.next(.universal, false, .object_identifier);
        return Enum.oids.get(self.view(ele)) orelse {
            const oid = Oid{ .bytes = self.view(ele) };
            var buffer: [256]u8 = undefined;
            var stream = std.io.fixedBufferStream(&buffer);
            oid.toString(stream.writer()) catch {};
            log.warn("unknown oid {s}", .{ stream.getWritten() });
            return error.UnknownObjectId;
        };
    }

    pub fn nextSequence(self: *Parser) !Element {
        return try self.next(.universal, true, .sequence);
    }

    pub fn nextSequenceOf(self: *Parser) !Element {
        return try self.next(.universal, true, .sequence_of);
    }

    pub fn nextPrimitive(self: *Parser, tag: ?Identifier.Tag) !Element {
        return try self.next(.universal, false, tag);
    }

    pub fn nextInteger(self: *Parser) !Element {
        var elem = try self.nextPrimitive(.integer);
        if (elem.slice.len() > 0) {
            if (self.view(elem)[0] == 0) elem.slice.start += 1;
            if (elem.slice.len() > 0 and self.view(elem)[0] == 0) return error.InvalidIntegerEncoding;
        }
        return elem;
    }

    pub fn nextInt(self: *Parser, comptime T: type) !T {
        const int = try self.nextInteger();
        const bytes = self.view(int);
        switch (@typeInfo(T)) {
            .Int => |info| {
                if (info.bits % 8 != 0) @compileError("DER only supports bytes");
                if (info.signedness != .signed) @compileError("DER only supports signed ints");

                return std.mem.readInt(T, bytes[0..info.bits / 8], .little);
            },
            else => @compileError(@typeName(T) ++ " is not an int type"),
        }
    }

    pub fn next(
        self: *Parser,
        class: ?Identifier.Class,
        constructed: ?bool,
        tag: ?Identifier.Tag,
    ) !Element {
        if (self.index >= self.bytes.len) return error.EndOfStream;

        const res = try Element.init(self.bytes, self.index);
        if (tag) |e| {
            if (res.identifier.tag != e) return error.UnexpectedElement;
        }
        if (constructed) |e| {
            if (res.identifier.constructed != e) return error.UnexpectedElement;
        }
        if (class) |e| {
            if (res.identifier.class != e) return error.UnexpectedElement;
        }
        self.index = if (res.identifier.constructed) res.slice.start else res.slice.end;
        return res;
    }

    pub fn view(self: Parser, elem: Element) []const u8 {
        return elem.slice.view(self.bytes);
    }

    pub fn seek(self: *Parser, index: u32) void {
        self.index = index;
    }
};

pub const Element = struct {
    identifier: Identifier,
    slice: Slice,

    pub const Slice = struct {
        start: u32,
        end: u32,

        pub fn len(self: Slice) u32 {
            return self.end - self.start;
        }

        pub fn view(self: Slice, bytes: []const u8) []const u8 {
            return bytes[self.start..self.end];
        }
    };

    pub fn init(bytes: []const u8, index: u32) !Element {
        var stream = std.io.fixedBufferStream(bytes[index..]);
        var reader = stream.reader();

        const identifier = @as(Identifier, @bitCast(try reader.readByte()));
        const size_or_len_size = try reader.readByte();

        var start = index + 2;
        // short form between 0-127
        if (size_or_len_size  < 128) {
            const end = start + size_or_len_size;
            if (end > bytes.len) return error.InvalidLength;

            return .{ .identifier = identifier, .slice = .{ .start = start, .end = end } };
        }

        // long form between 0 and std.math.maxInt(u1024)
        const len_size: u7 = @truncate(size_or_len_size);
        start += len_size;
        // cutoff at std.math.maxInt(u32)
        if (len_size > 4) return error.InvalidLength;
        const len = try reader.readVarInt(u32, .big, len_size);
        if (len < 128) return error.InvalidLength; // should have used short form

        const end = std.math.add(u32, start, len) catch return error.InvalidLength;
        if (end > bytes.len) return error.InvalidLength;

        return .{ .identifier = identifier, .slice = .{ .start = start, .end = end } };
    }
};

test "der element" {
    const short_form = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x09 };
    try std.testing.expectEqual(
        Element{
            .identifier = Identifier{ .tag  = .sequence, .constructed = true, .class = .universal },
            .slice = .{ .start = 2, .end = short_form.len },
        },
        Element.init(&short_form, 0)
    );

    const long_form = [_]u8{ 0x30, 129, 129 } ++ [_]u8{ 0 } ** 129;
    try std.testing.expectEqual(
        Element{
            .identifier = Identifier{ .tag  = .sequence, .constructed = true, .class = .universal },
            .slice = .{ .start = 3, .end = long_form.len },
        },
        Element.init(&long_form, 0)
    );
}

fn parseTimeDigits(
    text: *const [2]u8,
    min: comptime_int,
    max: comptime_int,
) !std.math.IntFittingRange(min, max) {
    const result = std.fmt.parseInt(std.math.IntFittingRange(min, max), text, 10) catch
        return error.InvalidDateTime;
    if (result < min) return error.InvalidTime;
    if (result > max) return error.InvalidTime;
    return result;
}

test parseTimeDigits {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(@as(u8, 0), try parseTimeDigits("00", 0, 99));
    try expectEqual(@as(u8, 99), try parseTimeDigits("99", 0, 99));
    try expectEqual(@as(u8, 42), try parseTimeDigits("42", 0, 99));

    const expectError = std.testing.expectError;
    try expectError(error.InvalidTime, parseTimeDigits("13", 1, 12));
    try expectError(error.InvalidTime, parseTimeDigits("00", 1, 12));
    try expectError(error.InvalidTime, parseTimeDigits("Di", 0, 99));
}

fn parseYear4(text: *const [4]u8) !i16 {
    const result = std.fmt.parseInt(i16, text, 10) catch return error.InvalidYear;
    if (result > 9999) return error.InvalidYear;
    return result;
}

test parseYear4 {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(@as(i16, 0), try parseYear4("0000"));
    try expectEqual(@as(i16, 9999), try parseYear4("9999"));
    try expectEqual(@as(i16, 1988), try parseYear4("1988"));

    const expectError = std.testing.expectError;
    try expectError(error.InvalidYear, parseYear4("999b"));
    try expectError(error.InvalidYear, parseYear4("crap"));
    try expectError(error.InvalidYear, parseYear4("r:bQ"));
}

fn parseTime(bytes: *const [6]u8) !std.Time {
    return .{
        .hour = try parseTimeDigits(bytes[0..2], 0, 23),
        .minute = try parseTimeDigits(bytes[2..4], 0, 59),
        .second = try parseTimeDigits(bytes[4..6], 0, 59),
    };
}

pub const Identifier = packed struct(u8) {
    tag: Tag,
    constructed: bool,
    class: Class,

    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,
    };

    // https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/asn1-tags.html
    pub const Tag = enum(u5) {
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        object_identifier = 6,
        real = 9,
        enumerated = 10,
        string_utf8 = 12,
        sequence = 16,
        /// a set
        sequence_of = 17,
        string_numeric = 18,
        string_printable = 19,
        string_teletex = 20,
        string_videotex = 21,
        string_ia5 = 22,
        utc_time = 23,
        generalized_time = 24,
        string_visible = 26,
        string_universal = 28,
        string_bmp = 30,
        _,
    };
};

pub const BitString = struct {
    bytes: []const u8,
    right_padding: u3,

    pub fn bitLen(self: BitString) usize {
        return self.bytes.len * 8 + self.right_padding;
    }
};

pub const Oid = struct {
    bytes: []const u8,

    const oid_base = 128;

    pub fn dotLen(dot_notation: []const u8) usize {
        var res: usize = 1;

        var split = std.mem.splitScalar(u8, dot_notation, '.');
        std.debug.assert(split.next() != null);
        std.debug.assert(split.next() != null);
        while (split.next()) |s| {
            const parsed = try std.fmt.parseUnsigned(usize, s, 10);
            const n_bytes = std.math.log(f64, oid_base, parsed);

            res += @intFromFloat(@ceil(n_bytes));
            res += 1;
        }

        return res;
    }

    pub fn fromString(dot_notation: []const u8, buf: []u8) !Oid {
        var split = std.mem.splitScalar(u8, dot_notation, '.');
        // optimization: store first two numbers in first byte
        const first = try std.fmt.parseInt(u8, split.next().?, 10);
        const second = try std.fmt.parseInt(u8, split.next().?, 10);

        buf[0] = first * 40 + second;

        var i: usize = 1;
        while (split.next()) |s| {
            // technically, any number should be supported.
            // however, let's be practical and set cutoff at usize
            var parsed = try std.fmt.parseUnsigned(usize, s, 10);
            const n_bytes = if (parsed == 0) 0 else std.math.log(usize, oid_base, parsed);

            for (0..n_bytes) |j| {
                const place = std.math.pow(usize, oid_base, n_bytes - j);
                const digit: u8 = @intCast(@divFloor(parsed, place));

                buf[i] = digit | 0b10000000;
                parsed -= digit * place;

                i += 1;
            }
            buf[i] = @intCast(parsed);
            i += 1;
        }

        return .{ .bytes = buf[0..i] };
    }

    pub fn toString(self: Oid, writer: anytype) !void {
        const first = @divTrunc(self.bytes[0], 40);
        const second = self.bytes[0] - first * 40;
        try writer.print("{d}.{d}", .{ first, second });

        var i: usize = 1;
        while (i != self.bytes.len) {
            const n_bytes: usize = brk: {
                var res: usize = 1;
                var j: usize = i;
                while (self.bytes[j] & 0b10000000 != 0) {
                    res += 1;
                    j += 1;
                }
                break :brk res;
            };

            var n: usize = 0;
            for (0..n_bytes) |j| {
                const place = std.math.pow(usize, oid_base, n_bytes - j - 1);
                n += place * (self.bytes[i] & 0b01111111);
                i += 1;
            }
            try writer.print(".{d}", .{n});
        }
    }
};

fn testOid(expected: []const u8, dot_notation: []const u8) !void {
    var buf: [256]u8 = undefined;
    const oid = try Oid.fromString(dot_notation, &buf);
    try std.testing.expectEqualSlices(u8, expected, oid.bytes);
    var dotted_notation_buf: [256]u8 = undefined;
    var stream = std.io.fixedBufferStream(&dotted_notation_buf);
    try oid.toString(stream.writer().any());
    try std.testing.expectEqualStrings(dot_notation, stream.getWritten());
}

test Oid {
    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    try testOid(
        &[_]u8{ 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x14 },
        "1.3.6.1.4.1.311.21.20",
    );
    // https://luca.ntop.org/Teaching/Appunti/asn1.html
    try testOid(&[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, "1.2.840.113549");
    // https://www.sysadmins.lv/blog-en/how-to-encode-object-identifier-to-an-asn1-der-encoded-string.aspx
    try testOid(&[_]u8{ 0x2a, 0x86, 0x8d, 0x20 }, "1.2.100000");
    try testOid(
        &[_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b },
        "1.2.840.113549.1.1.11",
    );
    try testOid(&[_]u8{ 0x2b, 0x65, 0x70 }, "1.3.101.112");

    // const idk = hexToBytes("300d06092a864886f70d01010c0500");
    // const oid = Oid{ .bytes = idk };
    // var stream = std.io.getStdErr();
    // try oid.toDecimal(stream.writer().any());
    // try stream.writer().writeAll("\n");
}
