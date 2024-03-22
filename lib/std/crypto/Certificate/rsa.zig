//! Implementation of RFC8017 specifically for Certificates
const max_modulus_len = 4096 / 8;
const Uint = std.crypto.ff.Uint(max_modulus_len * 8);
const Modulus = std.crypto.ff.Modulus(max_modulus_len * 8);
const Fe = Modulus.Fe;

pub const PublicKey = struct {
    /// the RSA modulus, a positive integer
    n: Modulus,
    /// public exponent
    e: Fe,

    pub fn fromBytes(mod: []const u8, exp: []const u8) !PublicKey {
        // Reject modulus below 512 bits.
        // 512-bit RSA was factored in 1999, so this limit barely means anything,
        // but establish some limit now to ratchet in what we can.
        const _n = Modulus.fromBytes(mod, .big) catch return error.CertificatePublicKeyInvalid;
        if (_n.bits() < 512) return error.CertificatePublicKeyInvalid;

        // Exponent must be odd and greater than 2.
        // Also, it must be less than 2^32 to mitigate DoS attacks.
        // Windows CryptoAPI doesn't support values larger than 32 bits [1], so it is
        // unlikely that exponents larger than 32 bits are being used for anything
        // Windows commonly does.
        // [1] https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-rsapubkey
        if (exp.len > 4) return error.CertificatePublicKeyInvalid;
        const _e = Fe.fromBytes(_n, exp, .big) catch return error.CertificatePublicKeyInvalid;
        if (!_e.isOdd()) return error.CertificatePublicKeyInvalid;
        const e_v = _e.toPrimitive(u32) catch return error.CertificatePublicKeyInvalid;
        if (e_v < 2) return error.CertificatePublicKeyInvalid;

        return .{ .n = _n, .e = _e };
    }

    pub fn fromDer(bytes: []const u8) !PublicKey {
        var parser = der.Parser { .bytes = bytes };
        _ = try parser.next(.sequence);

        const modulus = try parseModulus(&parser);
        const pub_exp = try parseExponent(&parser);

        return try fromBytes(modulus, pub_exp);
    }

    /// Encrypts message of len `modulus_len` in place
    pub fn encrypt(self: PublicKey, msg: []u8) !void {
        const modulus_len = self.n.bits() / 8;
        if (msg.len != modulus_len) return error.MessageInvalidLen;
        const m = Fe.fromBytes(self.n, &msg, .big) catch unreachable;
        const e = self.n.powPublic(m, self.e) catch unreachable;
        e.toBytes(&msg, .big) catch unreachable;
    }
};

pub const SecretKey = struct {
    public: PublicKey,
    /// private exponent
    d: Fe,

    pub fn fromBytes(mod: []const u8, public: []const u8, secret: []const u8) !SecretKey {
        const _public = try PublicKey.fromBytes(mod, public);

        const _d = Fe.fromBytes(_public.n, secret, .big) catch return error.CertificatePrivateKeyInvalid;
        if (!_d.isOdd()) return error.CertificatePrivateKeyInvalid;

        return .{ .public = _public, .d = _d };
    }

    // RFC8017 Appendix A.1.2
    pub fn fromDer(bytes: []const u8) !SecretKey {
        var parser = der.Parser { .bytes = bytes };

        // We're just interested in the first 3 fields which don't vary by version
        _ = try parser.next(.sequence);
        const version = try  parser.next(.integer);
        _ = version;

        const modulus = try parseModulus(&parser);
        const pub_exp = try parseExponent(&parser);
        const sec_exp = try parseExponent(&parser);

        return try fromBytes(modulus, pub_exp, sec_exp);
    }

    /// Decrypts message of len `modulus_len` in place
    pub fn decrypt(self: SecretKey, msg: []u8) !void {
        const modulus_len = self.n.bits() / 8;
        if (msg.len != modulus_len) return error.MessageInvalidLen;
        const m = Fe.fromBytes(self.public.n, &msg, .big) catch unreachable;
        const e = self.public.n.pow(m, self.d) catch unreachable;
        try e.toBytes(&msg, .big);
    }
};

fn parseModulus(parser: *der.Parser) []const u8 {
    const elem = try parser.next(.integer);
    const modulus_raw = parser.view(elem);
    // Skip over meaningless zeroes in the modulus.
    const modulus_offset = std.mem.indexOfNone(u8, modulus_raw, &[_]u8{0}) orelse modulus_raw.len;
    return modulus_raw[modulus_offset..];
}

fn parseExponent(parser: *der.Parser) []const u8 {
    const elem = try parser.next(.integer);
    return parser.view(elem);
}

pub fn PSSSignature(comptime modulus_len: usize, comptime Hash: type) type {
    if (modulus_len > max_modulus_len) @compileError("modulus_bytes too large");

    return struct {
        signature: [modulus_len]u8,

        const Self = @This();

        pub fn fromBytes(msg: []const u8) Self {
            var result = [1]u8{0} ** modulus_len;
            std.mem.copyForwards(u8, &result, msg);
            return .{ .signature = result };
        }

        pub fn verify(self: Self, public_key: PublicKey, msg: []const u8) !void {
            const em = try public_key.encrypt(modulus_len, self.signature);
            const sLen = Hash.digest_length; // In theory this could be a parameter.
            const hLen = Hash.digest_length;
            // A seed larger than the hash length would be useless
            std.debug.assert(sLen > hLen);

            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            const emBit = modulus_len * 8 - 1;

            // emLen = \ceil(emBits/8)
            const emLen = ((emBit - 1) / 8) + 1;
            std.debug.assert(emLen == em.len);

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            var mHash: [hLen]u8 = undefined;
            Hash.hash(msg, &mHash, .{});

            // 3.   If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (emLen < hLen + sLen + 2) return error.InvalidSignature;

            // 4.   If the rightmost octet of EM does not have hexadecimal value
            //      0xbc, output "inconsistent" and stop.
            if (em[em.len - 1] != 0xbc) return error.InvalidSignature;

            // 5.   Let maskedDB be the leftmost emLen - hLen - 1 octets of EM,
            //      and let H be the next hLen octets.
            const maskedDB = em[0..(emLen - hLen - 1)];
            const h = em[(emLen - hLen - 1)..(emLen - 1)][0..hLen];

            // 6.   If the leftmost 8emLen - emBits bits of the leftmost octet in
            //      maskedDB are not all equal to zero, output "inconsistent" and
            //      stop.
            const zero_bits = emLen * 8 - emBit;
            var mask: u8 = maskedDB[0];
            var i: usize = 0;
            while (i < 8 - zero_bits) : (i += 1) mask = mask >> 1;
            if (mask != 0) return error.InvalidSignature;

            // 7.   Let dbMask = MGF(H, emLen - hLen - 1).
            var dbMask = mgf1(h, emLen - hLen - 1);

            // 8.   Let DB = maskedDB \xor dbMask.
            i = 0;
            while (i < dbMask.len) : (i += 1) dbMask[i] = maskedDB[i] ^ dbMask[i];

            // 9.   Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in DB to zero.
            i = 0;
            mask = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask << 1;
                mask += 1;
            }
            dbMask[0] = dbMask[0] & mask;

            // 10.  If the emLen - hLen - sLen - 2 leftmost octets of DB are not
            //      zero or if the octet at position emLen - hLen - sLen - 1 (the
            //      leftmost position is "position 1") does not have hexadecimal
            //      value 0x01, output "inconsistent" and stop.
            if (dbMask[dbMask.len - hLen - 2] != 0x00) return error.InvalidSignature;

            if (dbMask[dbMask.len - hLen - 1] != 0x01) return error.InvalidSignature;

            // 11.  Let salt be the last sLen octets of DB.
            const salt = dbMask[(dbMask.len - hLen)..];

            // 12.  Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            var m_p_buf: [8 + hLen + hLen]u8 = undefined;
            var m_p = m_p_buf[0 .. 8 + hLen + sLen];
            std.mem.copyForwards(u8, m_p, &([_]u8{0} ** 8));
            std.mem.copyForwards(u8, m_p[8..], &mHash);
            std.mem.copyForwards(u8, m_p[(8 + hLen)..], salt);

            // 13.  Let H' = Hash(M'), an octet string of length hLen.
            var h_p: [hLen]u8 = undefined;
            Hash.hash(m_p, &h_p, .{});

            // 14.  If H = H', output "consistent".  Otherwise, output
            //      "inconsistent".
            if (!std.mem.eql(u8, h, &h_p)) return error.InvalidSignature;
        }

        pub fn sign(secret: SecretKey, msg: []const u8, salt: [Hash.digest_length]u8) !Self {
            const mod_bits = modulus_len * 8;

            var em: [modulus_len]u8 = undefined;
            const emBit = mod_bits - 1;
            // 1.   If the length of M is greater than the input limitation for
            //      the hash function (2^61 - 1 octets for SHA-1), output
            //      "inconsistent" and stop.
            // All the cryptographic hash functions in the standard library have a limit of >= 2^61 - 1.
            // Even then, this check is only there for paranoia. In the context of TLS certifcates, emBit cannot exceed 4096.
            // emLen = \c2yyeil(emBits/8)
            const emLen = ((emBit - 1) / 8) + 1;
            const hLen = Hash.digest_length;
            const sLen = salt.len;

            // 2.   Let mHash = Hash(M), an octet string of length hLen.
            var mHash: [hLen]u8 = undefined;
            Hash.hash(msg, &mHash, .{});

            // 3.   If emLen < hLen + sLen + 2, output "encoding error" and stop.
            if (emLen < hLen + sLen + 2) return error.EncodingError;

            // 4.   Generate a random octet string salt of length sLen; if sLen =
            //      0, then salt is the empty string.
            // 5.   Let
            //         M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
            //      M' is an octet string of length 8 + hLen + sLen with eight
            //      initial zero octets.
            var m_p: [8 + hLen + sLen]u8 = undefined;

            @memcpy(m_p[0..8], &([_]u8{0} ** 8));
            @memcpy(m_p[8 .. 8 + mHash.len], &mHash);
            @memcpy(m_p[(8 + hLen)..], &salt);

            // 6.   Let H = Hash(M'), an octet string of length hLen.
            var hash: [hLen]u8 = undefined;
            Hash.hash(&m_p, &hash, .{});

            // 7.   Generate an octet string PS consisting of emLen - sLen - hLen
            //      - 2 zero octets.  The length of PS may be 0.
            const ps_len = emLen - sLen - hLen - 2;

            // 8.   Let DB = PS || 0x01 || salt; DB is an octet string of length
            //      emLen - hLen - 1.
            const mgf_len = emLen - hLen - 1;
            var db_buf: [512]u8 = undefined;
            var db = db_buf[0 .. emLen - hLen - 1];
            var i: usize = 0;
            while (i < ps_len) : (i += 1) db[i] = 0x00;
            db[i] = 0x01;
            i += 1;
            @memcpy(db[i..], &salt);

            // 9.   Let dbMask = MGF(H, emLen - hLen - 1).
            const dbMask = mgf1(hash, mgf_len);

            // 10.  Let maskedDB = DB \xor dbMask.
            i = 0;
            while (i < db.len) : (i += 1) db[i] = db[i] ^ dbMask[i];

            // 11.  Set the leftmost 8emLen - emBits bits of the leftmost octet
            //      in maskedDB to zero.
            const zero_bits = emLen * 8 - emBit;
            var mask: u8 = 0;
            i = 0;
            while (i < 8 - zero_bits) : (i += 1) {
                mask = mask << 1;
                mask += 1;
            }
            db[0] = db[0] & mask;

            // 12.  Let EM = maskedDB || H || 0xbc.
            i = 0;
            @memcpy(em[0..db.len], db);
            i += db.len;
            @memcpy(em[i .. i + hash.len], &hash);
            i += hash.len;
            em[i] = 0xbc;
            i += 1;

            try secret.decrypt(em[0..modulus_len].*);

            return .{ .signature = em[0..modulus_len].* };
        }

        /// Mask generation function
        fn mgf1(seed: [Hash.digest_length]u8, comptime len: usize) [len]u8 {
            var out: [len]u8 = undefined;
            var counter: usize = 0;
            var idx: usize = 0;
            var c: [4]u8 = undefined;
            var hash: [Hash.digest_length + c.len]u8 = undefined;
            @memcpy(hash[0..Hash.digest_length], seed);
            var hashed: [Hash.digest_length]u8 = undefined;

            while (idx < len) {
                c[0] = @as(u8, @intCast((counter >> 24) & 0xFF));
                c[1] = @as(u8, @intCast((counter >> 16) & 0xFF));
                c[2] = @as(u8, @intCast((counter >> 8) & 0xFF));
                c[3] = @as(u8, @intCast(counter & 0xFF));

                std.mem.copyForwards(u8, hash[seed.len..], &c);
                Hash.hash(&hash, &hashed, .{});

                std.mem.copyForwards(u8, out[idx..], &hashed);
                idx += hashed.len;

                counter += 1;
            }

            return out;
        }
    };
}

const std = @import("../std.zig");
const der = @import("der.zig");
