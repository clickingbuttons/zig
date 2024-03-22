pub const Parser = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn next(self: *Parser, expected_tag: ?Tag) !?Element {
        if (self.index >= self.bytes.len) return null;

        const res = try Element.parse(self.bytes[self.index..]);
        const tag = res.identifier.tag;
        if (expected_tag) |e| {
            if (tag != e) return error.UnexpectedElement;
        }
        self.index = if (tag == .sequence) res.start else res.end;
        return res;
    }

    pub fn view(self: Parser, elem: Element) []const u8 {
        return elem.view(self.bytes);
    }
};

pub const Element = struct {
    identifier: Identifier,
    start: u32,
    end: u32,

    pub const ParseElementError = error{InvalidLength};

    pub fn parse(bytes: []const u8, index: u32) ParseElementError!Element {
        var i = index;
        const identifier = @as(Identifier, @bitCast(bytes[i]));
        i += 1;
        const size_byte = bytes[i];
        i += 1;
        if ((size_byte >> 7) == 0) {
            return .{
                .identifier = identifier,
                .slice = .{
                    .start = i,
                    .end = i + size_byte,
                },
            };
        }

        const len_size = @as(u7, @truncate(size_byte));
        if (len_size > @sizeOf(u32)) return error.InvalidLength;

        const end_i = i + len_size;
        var long_form_size: u32 = 0;
        while (i < end_i) : (i += 1) {
            long_form_size = (long_form_size << 8) | bytes[i];
        }

        return .{
            .identifier = identifier,
            .slice = .{
                .start = i,
                .end = i + long_form_size,
            },
        };
    }

    pub fn view(self: Element, bytes: []const u8) []const u8 {
        return bytes[self.start..self.end];
    }
};

pub const Class = enum(u2) {
    universal,
    application,
    context_specific,
    private,
};

pub const PC = enum(u1) {
    primitive,
    constructed,
};

pub const Identifier = packed struct(u8) {
    tag: Tag,
    pc: PC,
    class: Class,
};

pub const Tag = enum(u5) {
    boolean = 1,
    integer = 2,
    bitstring = 3,
    octetstring = 4,
    null = 5,
    object_identifier = 6,
    sequence = 16,
    sequence_of = 17,
    utc_time = 23,
    generalized_time = 24,
    _,
};
