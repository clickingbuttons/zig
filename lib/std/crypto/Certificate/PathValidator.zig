//! RFC 5280 Section 6

path_len: PathLen = 0,
policy: Cert.Policy = Cert.Policy.any,
options: Options,

pub const Options = struct {
    issuer: Validator = .{
        .key_usage = .{ .key_cert_sign = .set_or_null },
    },
    subject: Validator = .{
        .key_usage = .{ .digital_signature = .set_or_null },
        .key_usage_ext = .{ .client_auth = .set_or_null },
    },
    /// Trusted Certificate Authorities.
    bundle: Bundle,
    // Unix epoch seconds.
    time: i64,

    pub const Validator = struct {
        key_usage: KeyUsage.Validator = .{},
        key_usage_ext: KeyUsageExt.Validator = .{},
    };
};
const Self = @This();

/// Check that `subject` is trusted CA in `options.bundle`.
pub fn validateCA(self: *Self, subject: Cert) !void {
    const issuer = self.options.bundle.issuers.get(subject.issuer) orelse return error.CANotFound;
    _ = try self.validate(subject, issuer);
}

/// Check `subject` is trusted by `issuer` by validating:
/// * `subject.issuer == issuer.subject`
/// * `subject` and `issuer` contain valid combinations of fields according to RFC 5280. SHA1
///   signature hashing algorithms are considered invalid.
/// * The time validity of the subject and issuer.
/// * `issuer.basic_constraints` are met.
/// * Subject and issuer key usage and extended key usage flags match those specified in options.
/// * If present, the issuer has at least one policy compatible with the subject's policy.
/// * `issuer.signature` is valid for `subject.tbs_bytes`. Valid algorithms are those listed in
///   Mozilla's Certificate policy [1], except for SHA1.
///
/// [1] https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/#5-certificates
pub fn validate(self: *Self, subject: Cert, issuer: Cert) !?Validated {
    if (!subject.issuer.eql(issuer.subject)) return error.CertificateIssuerMismatch;

    try subject.validate(self.options.time);
    try issuer.validate(self.options.time);

    try subject.key_usage.validate(self.options.subject.key_usage);
    try issuer.key_usage.validate(self.options.issuer.key_usage);
    try subject.key_usage_ext.validate(self.options.subject.key_usage_ext);
    try issuer.key_usage_ext.validate(self.options.issuer.key_usage_ext);

    var issuer_policies = issuer.policiesIter();
    const anyPolicy = comptimeOid("2.5.29.32.0");
    while (try issuer_policies.next()) |ip| brk: {
        if (std.mem.eql(u8, ip.oid.bytes, &anyPolicy)) break;

        var subject_policies = subject.policiesIter();
        while (try subject_policies.next()) |sp| {
            if (std.mem.eql(u8, ip.oid.bytes, sp.oid.bytes)) break :brk;
        }
        return error.IssuerPolicyNotMet;
    }

    const signature = Signature{
        .algo = subject.signature_algo,
        .value = try Signature.Value.fromBitString(issuer.pub_key, subject.signature),
    };
    try signature.verify(subject.tbs_bytes, issuer.pub_key);

    if (self.options.bundle.issuers.get(subject.issuer)) |ca| {
        return Validated{ .ca = ca, .policy = self.policy, .path_len = self.path_len };
    }

    return null;
}

pub const Validated = struct {
    ca: Cert,
    policy: Policy,
    path_len: PathLen,
};

test validateCA {
    if (builtin.os.tag == .wasi) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var bundle: Bundle = .{};
    defer bundle.deinit(allocator);
    try bundle.addCertsFromPem(allocator, @embedFile("../testdata/ca_bundle.pem"));

    const cert_bytes = @embedFile("../testdata/cert_lets_encrypt_r3.der");
    const cert = try Cert.fromDer(cert_bytes);

    var validator = Self{ .options = .{
        // Wed 2024-04-17
        .time = 1713312664,
        .bundle = bundle,
    } };
    try validator.validateCA(cert);
}

const std = @import("std");
const builtin = @import("builtin");
const Cert = std.crypto.Certificate;
const KeyUsage = Cert.KeyUsage;
const KeyUsageExt = Cert.KeyUsageExt;
const Signature = Cert.Signature;
const PathLen = Cert.PathLen;
const Policy = Cert.Policy;
const Bundle = Cert.Bundle;
const der = std.crypto.der;
const Oid = der.Oid;
const comptimeOid = der.comptimeOid;
