//! Internet X.509 Public Key Infrastructure Certificate
//! and Certificate Revocation List (CRL) Profile
//!
//! RFC 5280

version: Version,
serial_number: []const u8,
issuer: Name,
validity: Validity,
subject: Name,
pub_key: PubKey,
/// Extension. Since we don't allocate, get slices from `subjectAliasesIter()`
subject_aliases_raw_der: ?[]const u8 = null,
/// Extension for how `pub_key` may be used.
key_usage: ?KeyUsage = null,
/// Extension further specifying how `pub_key` may be used.
key_usage_ext: ?KeyUsageExt = null,
/// Extension specifying maximum number of non-self-issued intermediate certificates that may
/// follow this certificate in a valid certification path.
max_depth: ?u8 = null,
/// Means of identifying the public key corresponding to the private key used to
/// sign a CRL.  The identification can be based on either the key
/// identifier (the subject key identifier in the CRL signer's
/// certificate) or the issuer name and serial number.  This extension is
/// especially useful where an issuer has more than one signing key,
/// either due to multiple concurrent key pairs or due to changeover.
///
/// Conforming CRL issuers MUST use the key identifier method, and MUST
/// include this extension in all CRLs issued.
ca_pub_key: ?[]const u8 = null,
signature: Signature,

const Cert = @This();

pub const VerifyError = error{
    CertificateIssuerMismatch,
    CertificateNotYetValid,
    CertificateExpired,
};

/// This function verifies:
///  * That the subject's issuer is indeed the provided issuer.
///  * The time validity of the subject.
///  * The signature.
///  * Usage matches key usage (if present).
///  * Usage matches extended key usage (if present).
pub fn verify(subject_: Cert, issuer_: Cert, now_sec: i64) VerifyError!void {
    // Check that the subject's issuer name matches the issuer's
    // subject name.
    if (!subject_.issuer.eql(issuer_.subject)) return error.CertificateIssuerMismatch;
    if (now_sec < subject_.validity.not_before) return error.CertificateNotYetValid;
    if (now_sec > subject_.validity.not_after) return error.CertificateExpired;

    try subject_.signature.verify(issuer_.pub_key);
}

pub const VerifyHostNameError = error{
    CertificateHostMismatch,
    CertificateFieldHasInvalidLength,
};

pub fn verifyHostName(sub: Cert, host_name: []const u8) VerifyHostNameError!void {
    // If the Subject Alternative Names extension is present, this is
    // what to check. Otherwise, only the common_name name is checked.
    const subject_alt_name = sub.subjectAltName();
    if (subject_alt_name.len == 0) {
        if (checkHostName(host_name, sub.common_nameName())) {
            return;
        } else {
            return error.CertificateHostMismatch;
        }
    }

    const general_names = try der.Element.init(subject_alt_name, 0);
    var name_i = general_names.slice.start;
    while (name_i < general_names.slice.end) {
        const general_name = try der.Element.init(subject_alt_name, name_i);
        name_i = general_name.slice.end;
        switch (@as(GeneralNameTag, @enumFromInt(@intFromEnum(general_name.identifier.tag)))) {
            .dNSName => {
                const dns_name = subject_alt_name[general_name.slice.start..general_name.slice.end];
                if (checkHostName(host_name, dns_name)) return;
            },
            else => {},
        }
    }

    return error.CertificateHostMismatch;
}

// Check hostname according to RFC2818 specification:
//
// If more than one identity of a given type is present in
// the certificate (e.g., more than one DNSName name, a match in any one
// of the set is considered acceptable.) Names may contain the wildcard
// character * which is considered to match any single domain name
// component or component fragment. E.g., *.a.com matches foo.a.com but
// not bar.foo.a.com. f*.com matches foo.com but not bar.com.
fn checkHostName(host_name: []const u8, dns_name: []const u8) bool {
    if (mem.eql(u8, dns_name, host_name)) {
        return true; // exact match
    }

    var it_host = std.mem.splitScalar(u8, host_name, '.');
    var it_dns = std.mem.splitScalar(u8, dns_name, '.');

    const len_match = while (true) {
        const host = it_host.next();
        const dns = it_dns.next();

        if (host == null or dns == null) {
            break host == null and dns == null;
        }

        // If not a wildcard and they dont
        // match then there is no match.
        if (mem.eql(u8, dns.?, "*") == false and mem.eql(u8, dns.?, host.?) == false) {
            return false;
        }
    };

    // If the components are not the same
    // length then there is no match.
    return len_match;
}

pub const ParseError = der.Parser.Error || error{};

pub fn fromDer(bytes: []const u8) !Cert {
    var parser = der.Parser{ .bytes = bytes };
    var res = Cert{
        .version = undefined,
        .serial_number = undefined,
        .issuer = undefined,
        .validity = undefined,
        .subject = undefined,
        .pub_key = undefined,
        .signature = undefined,
    };

    // this field appears early and MUST match the later `signature` field.
    var sig_algo: Algorithm = undefined;

    {
        const cert = try parser.nextSequence();
        defer parser.seek(cert.slice.end);

        {
            const cert_tbs = try parser.nextSequence();
            defer parser.seek(cert_tbs.slice.end);

            {
                const version_seq = try parser.next(.context_specific, true, @enumFromInt(0));
                defer parser.seek(version_seq.slice.end);

                const version_int = try parser.nextPrimitive(.integer);
                const version = parser.view(version_int);
                if (version.len != 1) return error.InvalidLength;
                res.version = @enumFromInt(version[0]);
            }

            const serial_number = try parser.nextPrimitive(.integer);
            res.serial_number = parser.view(serial_number);
            sig_algo = try Algorithm.fromDer(&parser);
            try sig_algo.validate();

            res.issuer = try Name.fromDer(&parser);
            res.validity = try Validity.fromDer(&parser);
            res.subject = try Name.fromDer(&parser);
            res.pub_key = try PubKey.fromDer(&parser);

            // final 3 fields are optional
            var optional_parsed: u8 = 0;
            while (parser.index != cert_tbs.slice.end and optional_parsed < 3) : (optional_parsed += 1) {
                const optional_ele = try parser.next(.context_specific, null, null);
                defer parser.seek(optional_ele.slice.end);

                switch (@intFromEnum(optional_ele.identifier.tag)) {
                    1, 2 => {
                        // skip issuerUniqueID or subjectUniqueID
                        _ = try parser.nextBitstring();
                    },
                    3 => {
                        try parseExtensions(&res, &parser);
                    },
                    else => return error.InvalidOptionalField,
                }
            }
        }

        const sig_algo2 = try Algorithm.fromDer(&parser);
        if (!std.meta.eql(sig_algo, sig_algo2)) return error.SigAlgoMismatch;

        const sig_bitstring = try parser.nextBitstring();
        const sig_value = try Signature.Value.fromBitString(res.pub_key, sig_bitstring);
        res.signature = .{ .algo = sig_algo, .value = sig_value };
    }

    return res;
}

fn parseExtensions(res: *Cert, parser: *der.Parser) !void {
    const ExtensionTag = enum {
        unknown,
        key_usage,
        subject_alt_name,
        authority_key_identifier,
        key_usage_ext,
        basic_constraints,

        pub const oids = std.ComptimeStringMap(@This(), .{
            .{ &comptimeOid("2.5.29.15"), .key_usage },
            .{ &comptimeOid("2.5.29.17"), .subject_alt_name },
            .{ &comptimeOid("2.5.29.35"), .authority_key_identifier },
            .{ &comptimeOid("2.5.29.37"), .key_usage_ext },
            .{ &comptimeOid("2.5.29.19"), .basic_constraints },
        });
    };
    const seq = try parser.nextSequence();
    defer parser.seek(seq.slice.end);

    while (parser.index != seq.slice.end) {
        const seq2 = try parser.nextSequence();
        defer parser.seek(seq2.slice.end);

        const tag = parser.nextEnum(ExtensionTag) catch |err| switch (err) {
            error.UnknownObjectId => .unknown,
            else => return err,
        };
        const critical = parser.nextBool() catch |err| switch (err) {
            error.UnexpectedElement => false,
            else => return err,
        };
        const doc = try parser.nextPrimitive(.octetstring);
        const doc_bytes = parser.view(doc);
        switch (tag) {
            .unknown => {
                if (critical) {
                    rsa.debugPrint("doc",  doc_bytes);
                    return error.UnimplementedCriticalExtension;
                }
            },
            .key_usage => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                res.key_usage = try KeyUsage.fromDer(&parser2);
            },
            .authority_key_identifier => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                const seq3 = try parser2.nextSequence();
                defer parser2.seek(seq3.slice.end);

                const pub_key_ele = try parser2.next(.context_specific, false, @enumFromInt(0));
                res.ca_pub_key = parser2.view(pub_key_ele);
            },
            .key_usage_ext => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                res.key_usage_ext = try KeyUsageExt.fromDer(&parser2);
            },
            .subject_alt_name => {
                res.subject_aliases_raw_der = doc_bytes;
            },
            .basic_constraints => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                const seq3 = try parser2.nextSequence();
                if (seq3.slice.len() > 0) {
                    const is_ca = try parser2.nextBool();
                    const max_depth = try parser2.nextInt(i8);
                    if (max_depth < 0) return error.InvalidBasicConstraints;
                    if (is_ca) res.max_depth = @bitCast(max_depth);
                }
            },
        }
    }
}

pub const SubjectAliasesIter = struct {
    parser: der.Parser,
    seq: der.Element,

    pub const Error = der.Parser.Error || error{InvalidSubjectAltString};

    /// Currently only supports rfc822Name and dnsName of section 4.2.1.6
    pub fn next(it: *@This()) Error!?[]const u8 {
        while (it.parser.index < it.seq.slice.end) {
            const ele = try it.parser.next(.context_specific, null, null);
            switch (@intFromEnum(ele.identifier.tag)) {
                1, // rfc822Name
                2, // dNSName
                => {
                    if (ele.identifier.tag != .string_ia5) return error.InvalidSubjectAltString;
                    return it.parser.view(ele);
                },
                else => {
                    // We don't support the rest of the spec here since we currently only care
                    // about verifying HTTPS.
                },
            }
        }
        return null;
    }

    /// Reset the iterator to the initial index
    pub fn reset(it: *@This()) void {
        it.parser.index = it.seq.slice.start;
    }
};

fn subjectAliasesIter(c: Cert) !SubjectAliasesIter {
    if (c.subject_aliases_raw_der) |bytes| {
        const parser = der.Parser{ .bytes = bytes };
        const seq = try parser.nextSequence();
        return SubjectAliasesIter{ .parser = parser, .seq = seq };
    } else {
        const parser = der.Parser{ .bytes = "" };
        const empty_ele = der.Element{
            .identifier = .{ .tag = .sequence, .constructed = true, .class = .universal },
            .slice = .{ .start = 0, .end = 0 },
        };
        return SubjectAliasesIter{ .parser = parser, .seq = empty_ele };
    }
}

const PubKeyTag = enum {
    rsa2048,
    rsa3072,
    rsa4096,
    ecdsa_p256,
    ecdsa_p384,
    ecdsa_secp256,
    ed25519,
};

pub const PubKey = union(PubKeyTag) {
    rsa2048: Rsa2048.PublicKey,
    rsa3072: Rsa3072.PublicKey,
    rsa4096: Rsa4096.PublicKey,
    ecdsa_p256: EcdsaP256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ecdsa_secp256: EcdsaSecP256.PublicKey,
    ed25519: Ed25519.PublicKey,

    const Algo = enum {
        rsa,
        ecdsa,
        ed25519,

        pub const oids = std.ComptimeStringMap(Algo, .{
            .{ &comptimeOid("1.2.840.113549.1.1.1"), .rsa },
            .{ &comptimeOid("1.2.840.10045.2.1"), .ecdsa },
            .{ &comptimeOid("1.3.101.112"), .ed25519 },
        });
    };

    pub fn fromDer(parser: *der.Parser) !PubKey {
        const seq = try parser.nextSequence();
        defer parser.seek(seq.slice.end);
        const seq2 = try parser.nextSequence();
        defer parser.seek(seq2.slice.end);

        const tag = try parser.nextEnum(Algo);
        switch (tag) {
            .rsa => {
                _ = try parser.nextPrimitive(.null);
                const bitstring = try parser.nextBitstring();
                if (bitstring.right_padding != 0) return error.InvalidKeyLength;

                var parser2 = der.Parser{ .bytes = bitstring.bytes };
                _ = try parser2.nextSequence();

                const mod = try rsa.parseModulus(&parser2);
                const elem = try parser2.nextPrimitive(.integer);
                const pub_exp = parser2.view(elem);
                return switch (mod.len * 8) {
                    2048 => return .{ .rsa2048 = try Rsa2048.PublicKey.fromBytes(mod, pub_exp) },
                    3072 => return .{ .rsa3072 = try Rsa3072.PublicKey.fromBytes(mod, pub_exp) },
                    4096 => return .{ .rsa4096 = try Rsa4096.PublicKey.fromBytes(mod, pub_exp) },
                    else => return error.InvalidRsaLength,
                };
            },
            .ecdsa => {
                const curve = try parser.nextEnum(NamedCurve);
                const bitstring = try parser.nextBitstring();
                if (bitstring.right_padding != 0) return error.InvalidKeyLength;

                return switch (curve) {
                    .prime256v1 => .{ .ecdsa_p256 = try EcdsaP256.PublicKey.fromSec1(bitstring.bytes) },
                    .secp384r1 => .{ .ecdsa_p384 = try EcdsaP384.PublicKey.fromSec1(bitstring.bytes) },
                    .secp521r1 => return error.CurveUnsupported,
                    .secp256k1 => .{ .ecdsa_secp256 = try EcdsaSecP256.PublicKey.fromSec1(bitstring.bytes) },
                };
            },
            .ed25519 => {
                _ = try parser.nextPrimitive(.null);
                const bitstring = try parser.nextBitstring();
                if (bitstring.right_padding != 0) return error.InvalidKeyLength;
                const expected_len = Ed25519.PublicKey.encoded_length;
                if (bitstring.bytes.len != expected_len) return error.InvalidKeyLength;
                const key = try Ed25519.PublicKey.fromBytes(bitstring.bytes[0..expected_len].*);

                return .{ .ed25519 = key };
            },
        }
    }
};

pub const Validity = struct {
    not_before: DateTime.EpochSubseconds,
    not_after: DateTime.EpochSubseconds,

    pub fn fromDer(parser: *der.Parser) !Validity {
        const seq = try parser.nextSequence();
        defer parser.seek(seq.slice.end);

        var res: Validity = undefined;
        res.not_before = (try parser.nextDateTime()).toEpoch();
        res.not_after = (try parser.nextDateTime()).toEpoch();
        return res;
    }
};

pub const Name = struct {
    country: []const u8 = "",
    organization: []const u8 = "",
    organizational_unit: []const u8 = "",
    distinguished_qualifier: []const u8 = "",
    state_or_province: []const u8 = "",
    common_name: []const u8 = "",
    serial_number: []const u8 = "",
    locality: []const u8 = "",
    title: []const u8 = "",
    surname: []const u8 = "",
    given_name: []const u8 = "",
    initials: []const u8 = "",
    pseudonym: []const u8 = "",
    generation_qualifier: []const u8 = "",

    pub fn fromDer(parser: *der.Parser) !Name {
        var res = Name{};
        const seq = try parser.nextSequence();

        while (parser.index != seq.slice.end) {
            const kv = try parser.nextSequenceOf();
            defer parser.index = kv.slice.end;

            _ = try parser.nextSequence();
            const key = try parser.nextEnum(Attribute);
            switch (key) {
                .countryName => res.country = try nextDirString(parser),
                .organizationName => res.organization = try nextDirString(parser),
                .organizationalUnitName => res.organizational_unit = try nextDirString(parser),
                .common_nameName => res.common_name = try nextDirString(parser),
                else => {
                    std.debug.print("bad key {}\n", .{key});
                },
            }
        }

        return res;
    }

    pub fn eql(self: Name, other: Name) bool {
        inline for (@typeInfo(Name).Struct.fields) |field| {
            if (!mem.eql(u8, @field(self, field.name), @field(other, field.name))) return false;
        }
        return true;
    }
};

pub const Version = enum(u8) {
    v1 = 0,
    v2 = 1,
    v3 = 2,
};

const NamedCurve = enum {
    prime256v1,
    secp256k1,
    secp384r1,
    secp521r1,

    pub const oids = std.ComptimeStringMap(@This(), .{
        .{ &comptimeOid("1.2.840.10045.3.1.7"), .prime256v1 },
        .{ &comptimeOid("1.3.132.0.10"), .secp256k1 },
        .{ &comptimeOid("1.3.132.0.34"), .secp384r1 },
        .{ &comptimeOid("1.3.132.0.35"), .secp521r1 },
    });
};

const AlgorithmTag = enum {
    rsa_pkcs_sha224,
    rsa_pkcs_sha256,
    rsa_pkcs_sha384,
    rsa_pkcs_sha512,
    rsa_pss,
    ecdsa_sha224,
    ecdsa_sha256,
    ecdsa_sha384,
    ecdsa_sha512,
    ed25519,

    pub const oids = std.ComptimeStringMap(AlgorithmTag, .{
        .{ &comptimeOid("1.2.840.113549.1.1.14"), .rsa_pkcs_sha224 },
        .{ &comptimeOid("1.2.840.113549.1.1.11"), .rsa_pkcs_sha256 },
        .{ &comptimeOid("1.2.840.113549.1.1.12"), .rsa_pkcs_sha384 },
        .{ &comptimeOid("1.2.840.113549.1.1.13"), .rsa_pkcs_sha512 },
        .{ &comptimeOid("1.2.840.113549.1.1.10"), .rsa_pss },
        .{ &comptimeOid("1.2.840.10045.4.3.1"), .ecdsa_sha224 },
        .{ &comptimeOid("1.2.840.10045.4.3.2"), .ecdsa_sha256 },
        .{ &comptimeOid("1.2.840.10045.4.3.3"), .ecdsa_sha384 },
        .{ &comptimeOid("1.2.840.10045.4.3.4"), .ecdsa_sha512 },
        .{ &comptimeOid("1.3.101.112"), .ed25519 },
    });
};

pub const Algorithm = union(enum) {
    rsa_pkcs: HashTag,
    rsa_pss: RsaPss,
    ecdsa: Ecdsa,
    ed25519: void,

    fn fromDer(parser: *der.Parser) !Algorithm {
        const seq = try parser.nextSequence();
        defer parser.seek(seq.slice.end);

        const algo = try parser.nextEnum(AlgorithmTag);
        switch (algo) {
            inline
            .rsa_pkcs_sha224,
            .rsa_pkcs_sha256,
            .rsa_pkcs_sha384,
            .rsa_pkcs_sha512,
            => |t| {
                _ = try parser.nextPrimitive(.null);
                const hash = std.meta.stringToEnum(HashTag, @tagName(t)["rsa_pkcs_".len..]).?;
                return .{ .rsa_pkcs = hash };
            },
            .rsa_pss => return .{ .rsa_pss = try RsaPss.fromDer(parser) },
            inline
            .ecdsa_sha224,
            .ecdsa_sha256,
            .ecdsa_sha384,
            .ecdsa_sha512,
            => |t| {
                const curve = if (parser.index != seq.slice.end) try parser.nextEnum(NamedCurve) else null;
                return .{
                    .ecdsa = Ecdsa{
                        .hash = std.meta.stringToEnum(HashTag, @tagName(t)["ecdsa_".len..]).?,
                        .curve = curve,
                    }
                };
            },
            .ed25519 => return .{ .ed25519 = {} },
        }
    }

    /// Make sure this algorithm is secure.
    /// Follows version of Mozilla's Certificate policy which additionally disallows SHA1.
    /// https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/#5-certificates
    fn validate(self: Algorithm) !void {
        switch (self) {
            .rsa_pkcs => |h| try h.validate(),
            .rsa_pss => |opts| try opts.hash.validate(),
            .ecdsa => |opts| try opts.hash.validate(),
            .ed25519 => {}, // always uses sha512
        }
    }

    // RFC 4055 S3.1
    const RsaPss = struct {
        hash: HashTag,
        mask_gen: MaskGen,
        salt_len: u8,

        pub fn fromDer(parser: *der.Parser) !RsaPss {
            const body = try parser.nextSequence();
            defer parser.seek(body.slice.end);

            const hash = brk: {
                const seq = try parser.nextSequence();
                defer parser.seek(seq.slice.end);
                const hash = try parser.nextEnum(HashTag);
                _ = try parser.nextPrimitive(.null);
                break :brk hash;
            };

            const mask_gen = try MaskGen.fromDer(parser);
            const salt_len = try parser.nextInt(i8);
            if (salt_len < 0) return error.InvalidSaltLength;

            return .{ .hash = hash, .mask_gen = mask_gen, .salt_len = @bitCast(salt_len) };
        }

        const MaskGen = struct {
            tag: Tag,
            hash: HashTag,

            pub fn fromDer(parser: *der.Parser) !MaskGen {
                const seq = try parser.nextSequence();
                defer parser.seek(seq.slice.end);

                const tag = try parser.nextEnum(Tag);
                const hash = try parser.nextEnum(HashTag);
                return .{ .tag = tag, .hash = hash };
            }

            const Tag = enum {
                mgf1,

                pub const oids = std.ComptimeStringMap(@This(), .{
                    .{ &comptimeOid("1.2.840.113549.1.1.8"), .mgf1 },
                });
            };
        };
    };

    const Ecdsa = struct {
        hash: HashTag,
        curve: ?NamedCurve,
    };
};

const HashTag = enum {
    sha1,
    sha224,
    sha256,
    sha384,
    sha512,
    sha512_224,
    sha512_256,

    pub const oids = std.ComptimeStringMap(@This(), .{
        .{ &comptimeOid("1.3.14.3.2.26"), .sha1 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.1"), .sha256 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.2"), .sha384 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.3"), .sha512 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.4"), .sha224 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.5"), .sha512_224 },
        .{ &comptimeOid("2.16.840.1.101.3.4.2.6"), .sha512_256 },
    });

    /// Returns error if not secure.
    pub fn validate(tag: HashTag) !void {
        switch (tag) {
            .sha1 => return error.InsecureHash,
            else => {},
        }
    }

    pub fn Hash(comptime self: HashTag) type {
        return switch (self) {
            .sha1 => return crypto.hash.Sha1,
            .sha224 => return crypto.hash.sha2.Sha224,
            .sha256 => return crypto.hash.sha2.Sha256,
            .sha384 => return crypto.hash.sha2.Sha384,
            .sha512 => return crypto.hash.sha2.Sha512,
            .sha512_224 => return crypto.hash.sha2.Sha512_224,
            .sha512_256 => return crypto.hash.sha2.Sha512_256,
        };
    }
};

pub const Signature = struct {
    algo: Algorithm,
    value: Value,

    const Value = union(PubKeyTag) {
        rsa2048: Rsa2048.Signature,
        rsa3072: Rsa3072.Signature,
        rsa4096: Rsa4096.Signature,
        ecdsa_p256: EcdsaP256.Signature,
        ecdsa_p384: EcdsaP384.Signature,
        ecdsa_secp256: EcdsaSecP256.Signature,
        ed25519: Ed25519.Signature,

        pub fn fromBitString(tag: PubKeyTag, bitstring: der.BitString) !Value {
            if (bitstring.right_padding != 0) return error.InvalidSignature;
            var parser = der.Parser{ .bytes = bitstring.bytes };

            switch (tag) {
                inline else => |t| {
                    const T = std.meta.FieldType(@This(), t);
                    const value = try T.fromDer(&parser);
                    return @unionInit(Value, @tagName(t), value);
                },
            }
        }
    };

    /// Verifies that this signature matches from `message` signed by `pub_key`
    pub fn verify(self: Signature, message: []const u8, pub_key: PubKey) !void {
        if (std.meta.activeTag(pub_key) != std.meta.activeTag(self.value)) return error.PublicKeyMismatch;

        switch (self.value) {
            .rsa2048, .rsa3072, .rsa4096 => |sig| {
                switch (self.algo) {
                    .rsa_pkcs => |hash| {
                        const Hash = switch (hash) {
                            inline else => |h| h.Hash(),
                        };
                        try sig.value.pss(Hash).verify(message, pub_key);
                    },
                    .rsa_pss => |opts| {
                        const Hash = switch (opts.hash) {
                            inline else => |h| h.Hash(),
                        };
                        if (opts.mask_gen != .mgf1) return error.UnsupportedMaskGenerationFunction;
                        try sig.value.pss(Hash).verify(message, pub_key, opts.salt_len);
                    },
                    else => return error.AlgorithmMismatch,
                }
            },
            .ecdsa_p256, .ecdsa_p384, .ecdsa_secp256 => |sig| {
                switch (self.algo) {
                    .ecdsa => |opts| {
                        try sig.verify(opts.hash, message, pub_key);
                    },
                    else => return error.AlgorithmMismatch,
                }
            },
            .ed25519_sha512 => |sig| {
                try sig.verify(message, pub_key);
            },
        }
    }

    const sha2 = crypto.hash.sha2;
    const Ecdsa = crypto.sign.ecdsa.Ecdsa;
};

pub const Attribute = enum {
    common_nameName,
    serialNumber,
    countryName,
    localityName,
    stateOrProvinceName,
    streetAddress,
    organizationName,
    organizationalUnitName,
    postalCode,
    organizationIdentifier,
    pkcs9_emailAddress,
    domainComponent,

    pub const oids = std.ComptimeStringMap(Attribute, .{
        .{ &comptimeOid("2.5.4.3"), .common_nameName },
        .{ &comptimeOid("2.5.4.5"), .serialNumber },
        .{ &comptimeOid("2.5.4.6"), .countryName },
        .{ &comptimeOid("2.5.4.7"), .localityName },
        .{ &comptimeOid("2.5.4.8"), .stateOrProvinceName },
        .{ &comptimeOid("2.5.4.9"), .streetAddress },
        .{ &comptimeOid("2.5.4.10"), .organizationName },
        .{ &comptimeOid("2.5.4.11"), .organizationalUnitName },
        .{ &comptimeOid("2.5.4.17"), .postalCode },
        .{ &comptimeOid("2.5.4.97"), .organizationIdentifier },
        .{ &comptimeOid("1.2.840.113549.1.9.1"), .pkcs9_emailAddress },
        .{ &comptimeOid("0.9.2342.19200300.100.1.25"), .domainComponent },
    });
};

pub const KeyUsage = packed struct {
    digital_signature: bool = false,
    content_commitment: bool = false,
    key_encipherment: bool = false,
    data_encipherment: bool = false,
    key_agreement: bool = false,
    key_cert_sign: bool = false,
    crl_sign: bool = false,
    encipher_only: bool = false,
    decipher_only: bool = false,

    pub fn fromDer(parser: *der.Parser) !KeyUsage {
        const bitstring = try parser.nextBitstring();

        var res = KeyUsage{};
        var bytes = mem.asBytes(&res);
        // copy what there is into our struct
        const to_copy = @min(bytes.len, bitstring.bytes.len);
        @memcpy(bytes[0..to_copy], bitstring.bytes[0..to_copy]);
        return res;
    }
};

pub const KeyUsageExt = struct {
    server_auth: bool = false,
    client_auth: bool = false,
    code_signing: bool = false,
    email_protection: bool = false,
    time_stamping: bool = false,
    ocsp_signing: bool = false,

    pub const Tag = enum {
        server_auth,
        client_auth,
        code_signing,
        email_protection,
        time_stamping,
        ocsp_signing,

        pub const oids = std.ComptimeStringMap(Tag, .{
            .{ &comptimeOid("1.3.6.1.5.5.7.3.1"), .server_auth },
            .{ &comptimeOid("1.3.6.1.5.5.7.3.2"), .client_auth },
            .{ &comptimeOid("1.3.6.1.5.5.7.3.3"), .code_signing },
            .{ &comptimeOid("1.3.6.1.5.5.7.3.4"), .email_protection },
            .{ &comptimeOid("1.3.6.1.5.5.7.3.8"), .time_stamping },
            .{ &comptimeOid("1.3.6.1.5.5.7.3.9"), .ocsp_signing },
        });
    };

    pub fn fromDer(parser: *der.Parser) !KeyUsageExt {
        var res: KeyUsageExt = .{};

        const seq = try parser.nextSequence();
        defer parser.seek(seq.slice.end);
        while (parser.index != parser.bytes.len) {
            const tag = parser.nextEnum(KeyUsageExt.Tag) catch |err| switch (err) {
                error.UnknownObjectId => continue,
                else => return err,
            };
            switch (tag) {
                .server_auth => res.server_auth = true,
                .client_auth => res.client_auth = true,
                .code_signing => res.code_signing = true,
                .email_protection => res.email_protection = true,
                .time_stamping => res.time_stamping = true,
                .ocsp_signing => res.ocsp_signing = true,
            }
        }

        return res;
    }
};

pub const GeneralNameTag = enum(u5) {
    otherName = 0,
    rfc822Name = 1,
    dNSName = 2,
    x400Address = 3,
    directoryName = 4,
    ediPartyName = 5,
    uniformResourceIdentifier = 6,
    iPAddress = 7,
    registeredID = 8,
    _,
};

fn nextDirString(parser: *der.Parser) ![]const u8 {
    const ele = try parser.next(.universal, false, null);
    switch (ele.identifier.tag) {
        .string_teletex, .string_printable, .string_universal, .string_utf8, .string_bmp => {
            return parser.view(ele);
        },
        else => return error.InvalidDirectoryString,
    }
}

fn comptimeOidFromString(comptime bytes: []const u8) Oid {
    @setEvalBranchQuota(10_000);
    var buf: [256]u8 = undefined;
    return Oid.fromString(bytes, &buf) catch unreachable;
}

fn comptimeOid(comptime bytes: []const u8) [comptimeOidFromString(bytes).bytes.len]u8 {
    const oid = comptimeOidFromString(bytes);
    return oid.bytes[0..oid.bytes.len].*;
}

const std = @import("../std.zig");
const crypto = std.crypto;
const mem = std.mem;
const DateTime = std.date_time.DateTime;
const Certificate = @This();
const der = @import("der.zig");
const Oid = der.Oid;
const rsa = @import("rsa.zig");
const ecdsa = crypto.sign.ecdsa;
const sha2 = crypto.hash.sha2;
const testing = std.testing;
pub const Bundle = @import("Certificate/Bundle.zig");

const Rsa2048 = rsa.Rsa2048;
const Rsa3072 = rsa.Rsa3072;
const Rsa4096 = rsa.Rsa4096;
const EcdsaP256 = ecdsa.Ecdsa(crypto.ecc.P256);
const EcdsaP384 = ecdsa.Ecdsa(crypto.ecc.P384);
const EcdsaSecP256 = ecdsa.Ecdsa(crypto.ecc.Secp256k1);
const Ed25519 = crypto.sign.Ed25519;

test {
    _ = Bundle;
}

/// Strictly for testing
inline fn hexToBytes(comptime hex: []const u8) []u8 {
    var res: [hex.len]u8 = undefined;
    return std.fmt.hexToBytes(&res, hex) catch unreachable;
}

test fromDer {
    // exact same cert as https://tls13.xargs.org/certificate.html
    // can also verify with:
    // $ openssl x509 -inform der -in ./testdata/cert.der -noout -text
    const cert_bytes = @embedFile("testdata/cert.der");
    const cert = try Cert.fromDer(cert_bytes);

    try testing.expectEqual(Version.v3, cert.version);
    try testing.expectEqualSlices(u8, hexToBytes("155a92adc2048f90"), cert.serial_number);
    try testing.expectEqualStrings("US", cert.issuer.country);
    try testing.expectEqualStrings("Example CA", cert.issuer.organization);
    try testing.expectEqual(1538703497, cert.validity.not_before);
    try testing.expectEqual(1570239497, cert.validity.not_after);
    try testing.expectEqualStrings("US", cert.subject.country);
    try testing.expectEqualStrings("example.ulfheim.net", cert.subject.common_name);
    try testing.expectEqual(PubKey.rsa2048, std.meta.activeTag(cert.pub_key));
    try testing.expectEqual(@as(usize, 65537), try cert.pub_key.rsa2048.public_exponent.toPrimitive(usize));
    try testing.expectEqual(Algorithm{ .rsa_pkcs = .sha256 }, cert.signature.algo);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x59, 0x16 }, cert.signature.value.rsa2048.bytes[0..2]);
}

test "fromDer ecda" {
    const cert_bytes = @embedFile("testdata/cert_ecdsa.der");
    const cert = try Cert.fromDer(cert_bytes);

    try testing.expectEqual(Version.v3, cert.version);
}
