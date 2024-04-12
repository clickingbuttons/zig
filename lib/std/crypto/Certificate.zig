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
    var sig_algo: SignatureTag = undefined;

    {
        const cert = try parser.nextSequence();
        defer parser.seekEnd(cert.slice.end);

        {
            const cert_tbs = try parser.nextSequence();
            defer parser.seekEnd(cert_tbs.slice.end);

            {
                const version_seq = try parser.next(.context_specific, true, @enumFromInt(0));
                defer parser.seekEnd(version_seq.slice.end);

                const version_int = try parser.nextPrimitive(.integer);
                const version = parser.view(version_int);
                if (version.len != 1) return error.InvalidLength;
                res.version = @enumFromInt(version[0]);
            }

            const serial_number = try parser.nextPrimitive(.integer);
            res.serial_number = parser.view(serial_number);
            sig_algo = try SignatureTag.fromDer(&parser);

            res.issuer = try Name.fromDer(&parser);
            res.validity = try Validity.fromDer(&parser);
            res.subject = try Name.fromDer(&parser);
            res.pub_key = try PubKey.fromDer(&parser);

            // final 3 fields are optional
            var optional_parsed: u8 = 0;
            while (parser.index != cert_tbs.slice.end and optional_parsed < 3) : (optional_parsed += 1) {
                const optional_ele = try parser.next(.context_specific, null, null);
                defer parser.seekEnd(optional_ele.slice.end);

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

        const sig_algo2 = try SignatureTag.fromDer(&parser);
        if (sig_algo != sig_algo2) return error.SigAlgoMismatch;

        const sig_bitstring = try parser.nextBitstring();
        res.signature = try Signature.fromPubKey(sig_algo, res.pub_key, sig_bitstring);
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

        pub const oids = std.ComptimeStringMap(@This(), .{
            .{ encodedOid("2.5.29.15"), .key_usage },
            .{ encodedOid("2.5.29.17"), .subject_alt_name },
            .{ encodedOid("2.5.29.35"), .authority_key_identifier },
            .{ encodedOid("2.5.29.37"), .key_usage_ext },
        });
    };
    const seq = try parser.nextSequence();
    defer parser.seekEnd(seq.slice.end);

    while (parser.index != seq.slice.end) {
        const seq2 = try parser.nextSequence();
        defer parser.seekEnd(seq2.slice.end);

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
                if (critical) return error.UnimplementedCriticalExtension;
            },
            .key_usage => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                res.key_usage = try KeyUsage.fromDer(&parser2);
            },
            .authority_key_identifier => {
                var parser2 = der.Parser{ .bytes = doc_bytes };
                const seq3 = try parser2.nextSequence();
                defer parser2.seekEnd(seq3.slice.end);

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

pub const PubKey = union(enum) {
    rsa2048: Rsa2048.PublicKey,
    rsa4096: Rsa4096.PublicKey,
    ecdsa_p256: EcdsaP256.PublicKey,
    ecdsa_p384: EcdsaP384.PublicKey,
    ed25519: crypto.sign.Ed25519.PublicKey,

    const EcdsaP256 = crypto.sign.ecdsa.EcdsaP256Sha256;
    const EcdsaP384 = crypto.sign.ecdsa.EcdsaP384Sha384;

    const Algo = enum {
        rsa,
        ecdsa,
        ed25519,

        pub const oids = std.ComptimeStringMap(Algo, .{
            .{ encodedOid("1.2.840.113549.1.1.1"), .rsa },
            .{ encodedOid("1.2.840.10045.2.1"), .ecdsa },
            .{ encodedOid("1.3.101.112"), .ed25519 },
        });
    };

    pub fn fromDer(parser: *der.Parser) !PubKey {
        const seq = try parser.nextSequence();
        defer parser.seekEnd(seq.slice.end);
        const seq2 = try parser.nextSequence();
        defer parser.seekEnd(seq2.slice.end);

        const tag = try parser.nextEnum(Algo);
        switch (tag) {
            .rsa => {
                _ = try parser.nextPrimitive(.null);
                const bitstring = try parser.nextBitstring();
                if (bitstring.right_padding != 0) return error.InvalidKeyLength;

                var parser2 = der.Parser{ .bytes = bitstring.bytes };
                _ = try parser2.nextSequence();

                const mod = try rsa.parseModulus(&parser2);
                return switch (mod.len * 8) {
                    2048 => return .{ .rsa2048 = try Rsa2048.PublicKey.fromDer(bitstring.bytes) },
                    4096 => return .{ .rsa4096 = try Rsa4096.PublicKey.fromDer(bitstring.bytes) },
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
                };
            },
            .ed25519 => {
                _ = try parser.nextPrimitive(.null);
                const bitstring = try parser.nextBitstring();
                if (bitstring.right_padding != 0) return error.InvalidKeyLength;
                const PublicKey = crypto.sign.Ed25519.PublicKey;
                if (bitstring.bytes.len != PublicKey.encoded_length) return error.InvalidKeyLength;
                const key = try PublicKey.fromBytes(bitstring.bytes[0..PublicKey.encoded_length].*);

                return .{ .ed25519 = key };
            },
        }
    }
};

pub const Validity = struct {
    not_before: u64,
    not_after: u64,

    pub fn fromDer(parser: *der.Parser) !Validity {
        const seq = try parser.nextSequence();
        defer parser.seekEnd(seq.slice.end);

        var res: Validity = undefined;
        res.not_before = (try parser.nextDateTime()).toSeconds();
        res.not_after = (try parser.nextDateTime()).toSeconds();
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

// Used in signature and public key headers
const NamedCurve = enum {
    prime256v1,
    secp384r1,

    pub const oids = std.ComptimeStringMap(NamedCurve, .{
        .{ encodedOid("1.2.840.10045.3.1.7"), .prime256v1 },
        .{ encodedOid("1.3.132.0.34"), .secp384r1 },
    });
};

pub const SignatureTag = enum {
    rsa_sha224,
    rsa_sha256,
    rsa_sha384,
    rsa_sha512,
    ecdsa_p256_sha224,
    ecdsa_p256_sha256,
    ecdsa_p256_sha384,
    ecdsa_p256_sha512,
    ecdsa_p384_sha224,
    ecdsa_p384_sha256,
    ecdsa_p384_sha384,
    ecdsa_p384_sha512,
    ed25519_sha512,

    pub fn fromDer(parser: *der.Parser) !SignatureTag {
        const seq = try parser.nextSequence();
        defer parser.seekEnd(seq.slice.end);

        const algo = try parser.nextEnum(Algorithm);
        switch (algo) {
            inline .rsa_sha224,
            .rsa_sha256,
            .rsa_sha384,
            .rsa_sha512,
            .ed25519_sha512,
            => |t| {
                _ = try parser.nextPrimitive(.null);
                return std.meta.stringToEnum(SignatureTag, @tagName(t)).?;
            },
            .ecdsa_sha224 => {
                const curve = try parser.nextEnum(NamedCurve);
                return switch (curve) {
                    .prime256v1 => .ecdsa_p256_sha224,
                    .secp384r1 => .ecdsa_p384_sha224,
                };
            },
            .ecdsa_sha256 => {
                const curve = try parser.nextEnum(NamedCurve);
                return switch (curve) {
                    .prime256v1 => .ecdsa_p256_sha256,
                    .secp384r1 => .ecdsa_p384_sha256,
                };
            },
            .ecdsa_sha384 => {
                const curve = try parser.nextEnum(NamedCurve);
                return switch (curve) {
                    .prime256v1 => .ecdsa_p256_sha384,
                    .secp384r1 => .ecdsa_p384_sha384,
                };
            },
            .ecdsa_sha512 => {
                const curve = try parser.nextEnum(NamedCurve);
                return switch (curve) {
                    .prime256v1 => .ecdsa_p256_sha512,
                    .secp384r1 => .ecdsa_p384_sha512,
                };
            },
        }
    }

    const Algorithm = enum {
        rsa_sha224,
        rsa_sha256,
        rsa_sha384,
        rsa_sha512,
        ecdsa_sha224,
        ecdsa_sha256,
        ecdsa_sha384,
        ecdsa_sha512,
        ed25519_sha512,

        pub const oids = std.ComptimeStringMap(Algorithm, .{
            .{ encodedOid("1.2.840.113549.1.1.14"), .rsa_sha224 },
            .{ encodedOid("1.2.840.113549.1.1.11"), .rsa_sha256 },
            .{ encodedOid("1.2.840.113549.1.1.12"), .rsa_sha384 },
            .{ encodedOid("1.2.840.113549.1.1.13"), .rsa_sha512 },
            .{ encodedOid("1.2.840.10045.4.3.1"), .ecdsa_sha224 },
            .{ encodedOid("1.2.840.10045.4.3.2"), .ecdsa_sha256 },
            .{ encodedOid("1.2.840.10045.4.3.3"), .ecdsa_sha384 },
            .{ encodedOid("1.2.840.10045.4.3.4"), .ecdsa_sha512 },
            .{ encodedOid("1.3.101.112"), .ed25519_sha512 },
        });
    };
};

/// Currently supports TLS signature schemes.
/// https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme
pub const Signature = union(enum) {
    rsa2048_sha224: Rsa2048.PKCS1v1_5(sha2.Sha224).Signature,
    rsa2048_sha256: Rsa2048.PKCS1v1_5(sha2.Sha256).Signature,
    rsa2048_sha384: Rsa2048.PKCS1v1_5(sha2.Sha384).Signature,
    rsa2048_sha512: Rsa2048.PKCS1v1_5(sha2.Sha512).Signature,
    rsa4096_sha224: Rsa4096.PKCS1v1_5(sha2.Sha224).Signature,
    rsa4096_sha256: Rsa4096.PKCS1v1_5(sha2.Sha256).Signature,
    rsa4096_sha384: Rsa4096.PKCS1v1_5(sha2.Sha384).Signature,
    rsa4096_sha512: Rsa4096.PKCS1v1_5(sha2.Sha512).Signature,
    ecdsa_p256_sha256: crypto.sign.ecdsa.EcdsaP256Sha256.Signature,
    ecdsa_p384_sha384: crypto.sign.ecdsa.EcdsaP384Sha384.Signature,
    ed25519_sha512: crypto.sign.Ed25519.Signature,

    pub fn fromPubKey(tag: SignatureTag, key: PubKey, bitstring: der.BitString) !Signature {
        switch (tag) {
            inline .rsa_sha224, .rsa_sha256, .rsa_sha384, .rsa_sha512 => |sig_tag| {
                const hash = @tagName(sig_tag)["rsa_".len..];
                switch (key) {
                    inline .rsa2048, .rsa4096 => |_, fam_tag| return fromTag(@tagName(fam_tag) ++ "_" ++ hash, bitstring),
                    else => return error.SignaturePubKeyMismatch,
                }
            },
            inline .ecdsa_p256_sha224,
            .ecdsa_p256_sha256,
            .ecdsa_p256_sha384,
            .ecdsa_p256_sha512,
            .ecdsa_p384_sha224,
            .ecdsa_p384_sha256,
            .ecdsa_p384_sha384,
            .ecdsa_p384_sha512,
            => |sig_tag| {
                const hash = @tagName(sig_tag)["ecdsa_p384_".len..];
                switch (key) {
                    inline .ecdsa_p256, .ecdsa_p384 => |_, fam_tag| return fromTag(@tagName(fam_tag) ++ "_" ++ hash, bitstring),
                    else => return error.SignaturePubKeyMismatch,
                }
            },
            .ed25519_sha512 => switch (key) {
                inline .ed25519 => return fromTag("ed25519_sha512", bitstring),
                else => return error.SignaturePubKeyMismatch,
            },
        }
    }

    fn fromTag(comptime sig_tag: []const u8, bitstring: der.BitString) !Signature {
        const SigT = std.meta.TagPayloadByName(Signature, sig_tag);
        if (bitstring.bytes.len - bitstring.right_padding != SigT.encoded_length)
            return error.InvalidSignatureLen;
        const sig = SigT.fromBytes(bitstring.bytes[0..SigT.encoded_length].*);
        return @unionInit(Signature, sig_tag, sig);
    }

    pub const VerifyError = error{InvalidSignature};

    /// Verifies that this signature matches from `message` signed by `pub_key`
    pub fn verify(self: Signature, message: []const u8, pub_key: PubKey) Signature.VerifyError!void {
        switch (self) {
            inline .rsa2048_sha224,
            .rsa2048_sha256,
            .rsa2048_sha384,
            .rsa2048_sha512,
            .rsa4096_sha224,
            .rsa4096_sha256,
            .rsa4096_sha384,
            .rsa4096_sha512,
            => |sig| {
                switch (pub_key) {
                    inline .rsa2048, .rsa4096 => |pk| {
                        sig.verify(message, pk) catch return error.PublicKeyMismatch;
                    },
                    else => return error.PublicKeyMismatch,
                }
            },
            inline .ecdsa_p256_sha224,
            .ecdsa_p256_sha256,
            .ecdsa_p256_sha384,
            .ecdsa_p256_sha512,
            .ecdsa_p384_sha224,
            .ecdsa_p384_sha256,
            .ecdsa_p384_sha384,
            .ecdsa_p384_sha512,
            => |sig| {
                switch (pub_key) {
                    inline .ecdsa_p256, .ecdsa_p384 => |pk| {
                        sig.verify(message, pk) catch |err| switch (err) {
                            error.IdentityElement,
                            error.NonCanonical,
                            error.SignatureVerificationFailed,
                            => return error.InvalidSignature,
                        };
                    },
                    else => return error.PublicKeyMismatch,
                }
            },
            .ed25519_sha512 => |sig| {
                switch (pub_key) {
                    inline .ed25519 => |pk| {
                        sig.verify(message, pk) catch |err| switch (err) {
                            error.IdentityElement,
                            error.NonCanonical,
                            error.SignatureVerificationFailed,
                            error.InvalidEncoding,
                            error.WeakPublicKey,
                            => return error.InvalidSignature,
                        };
                    },
                    else => return error.PublicKeyMismatch,
                }
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
        .{ encodedOid("2.5.4.3"), .common_nameName },
        .{ encodedOid("2.5.4.5"), .serialNumber },
        .{ encodedOid("2.5.4.6"), .countryName },
        .{ encodedOid("2.5.4.7"), .localityName },
        .{ encodedOid("2.5.4.8"), .stateOrProvinceName },
        .{ encodedOid("2.5.4.9"), .streetAddress },
        .{ encodedOid("2.5.4.10"), .organizationName },
        .{ encodedOid("2.5.4.11"), .organizationalUnitName },
        .{ encodedOid("2.5.4.17"), .postalCode },
        .{ encodedOid("2.5.4.97"), .organizationIdentifier },
        .{ encodedOid("1.2.840.113549.1.9.1"), .pkcs9_emailAddress },
        .{ encodedOid("0.9.2342.19200300.100.1.25"), .domainComponent },
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
            .{ encodedOid("1.3.6.1.5.5.7.3.1"), .server_auth },
            .{ encodedOid("1.3.6.1.5.5.7.3.2"), .client_auth },
            .{ encodedOid("1.3.6.1.5.5.7.3.3"), .code_signing },
            .{ encodedOid("1.3.6.1.5.5.7.3.4"), .email_protection },
            .{ encodedOid("1.3.6.1.5.5.7.3.8"), .time_stamping },
            .{ encodedOid("1.3.6.1.5.5.7.3.9"), .ocsp_signing },
        });
    };

    pub fn fromDer(parser: *der.Parser) !KeyUsageExt {
        var res: KeyUsageExt = .{};

        const seq = try parser.nextSequence();
        defer parser.seekEnd(seq.slice.end);
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

fn verifyEd25519(
    message: []const u8,
    encoded_sig: []const u8,
    pub_key_algo: Cert.PubKeyAlgo,
    encoded_pub_key: []const u8,
) !void {
    if (pub_key_algo != .curveEd25519) return error.CertificateSignatureAlgorithmMismatch;
    const Ed25519 = crypto.sign.Ed25519;
    if (encoded_sig.len != Ed25519.Signature.encoded_length) return error.CertificateSignatureInvalid;
    const sig = Ed25519.Signature.fromBytes(encoded_sig[0..Ed25519.Signature.encoded_length].*);
    if (encoded_pub_key.len != Ed25519.PublicKey.encoded_length) return error.CertificateSignatureInvalid;
    const pub_key = Ed25519.PublicKey.fromBytes(encoded_pub_key[0..Ed25519.PublicKey.encoded_length].*) catch |err| switch (err) {
        error.NonCanonical => return error.CertificateSignatureInvalid,
    };
    sig.verify(message, pub_key) catch |err| switch (err) {
        error.IdentityElement => return error.CertificateSignatureInvalid,
        error.NonCanonical => return error.CertificateSignatureInvalid,
        error.SignatureVerificationFailed => return error.CertificateSignatureInvalid,
        error.InvalidEncoding => return error.CertificateSignatureInvalid,
        error.WeakPublicKey => return error.CertificateSignatureInvalid,
    };
}

fn nextDirString(parser: *der.Parser) ![]const u8 {
    const ele = try parser.next(.universal, false, null);
    switch (ele.identifier.tag) {
        .string_teletex, .string_printable, .string_universal, .string_utf8, .string_bmp => {
            return parser.view(ele);
        },
        else => return error.InvalidDirectoryString,
    }
}

fn encodedOid(comptime bytes: []const u8) []const u8 {
    @setEvalBranchQuota(10000);
    const oid = Oid.fromDot(bytes) catch unreachable;
    return oid.bytes;
}

const std = @import("../std.zig");
const crypto = std.crypto;
const mem = std.mem;
const DateTime = std.date_time.DateTime;
const Certificate = @This();
const der = @import("der.zig");
const Oid = der.Oid;
const rsa = @import("rsa.zig");
const Rsa2048 = crypto.rsa.Rsa2048;
const Rsa4096 = crypto.rsa.Rsa4096Sha512;
const testing = std.testing;
pub const Bundle = @import("Certificate/Bundle.zig");

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
    // can also verify with `openssl`
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
    try testing.expectEqual(@as(usize, 65537), try cert.pub_key.rsa2048.e.toPrimitive(usize));
    try testing.expectEqual(Signature.rsa2048_sha256, std.meta.activeTag(cert.signature));
    try testing.expectEqualSlices(u8, &[_]u8{ 0x59, 0x16 }, cert.signature.rsa2048_sha256.bytes[0..2]);
}
