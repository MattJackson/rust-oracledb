#![forbid(unsafe_code)]
//! The OCI IAM database-token proof-of-possession signing string (python-oracledb thin
//! `messages/auth.pyx` `_write_message` + `impl/thin/crypto.pyx` `get_signature`). The signature
//! itself is the caller's (RSASSA-PKCS1-v1_5 SHA-256 under the token's bound key); this module
//! only builds the bytes it signs.

/// `date: <IMF-fixdate>\n(request-target): <service_name>\nhost: <host>:<port>`, byte for byte as
/// the reference signs it. `unix_secs` is the current UTC time (the server checks freshness).
pub fn build_signing_header(service: &str, host: &str, port: u16, unix_secs: u64) -> String {
    format!(
        "date: {}\n(request-target): {service}\nhost: {host}:{port}",
        crate::httpdate_of(unix_secs)
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn header_matches_reference_format() {
        assert_eq!(
            super::build_signing_header(
                "adb.example.db.example.com",
                "10.0.0.5",
                1522,
                1_784_271_600
            ),
            "date: Fri, 17 Jul 2026 07:00:00 GMT\n\
             (request-target): adb.example.db.example.com\n\
             host: 10.0.0.5:1522"
        );
    }
}
