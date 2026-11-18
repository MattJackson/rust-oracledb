#![forbid(unsafe_code)]
//! TCPS authentication: a session whose database user is identified by the client certificate the
//! TLS layer presented (`CREATE USER … IDENTIFIED EXTERNALLY AS '<subject DN>'`, server
//! `SQLNET.AUTHENTICATION_SERVICES=(TCPS)` with `SSL_CLIENT_AUTHENTICATION=TRUE`).
//!
//! The wire behaviour is python-oracledb thin's `externalauth` over a `tcps` address with a client
//! wallet (src/oracledb/impl/thin: messages/connect.pyx, connection.pyx `_connect_with_address`,
//! messages/network_services.pyx, messages/auth.pyx), the JDBC thin driver's
//! `oracle.net.authentication_services=(TCPS)` path:
//!
//! 1. CONNECT leaves network authentication enabled ([`super::build_connect_packet_payload_tcps_auth`]:
//!    no `TNS_NSI_DISABLE_NA`).
//! 2. Right after ACCEPT the client sends one network-services (ANO) DATA packet
//!    ([`build_network_services_tcps_auth`]): supervisor, authentication (`tcps`, id 2), encryption
//!    (none) and data integrity (none). The server answers with its own service list
//!    ([`parse_network_services_reply`]); its authentication status says whether the TCPS adapter
//!    took the session (`0xfaff`) or the server does not use network authentication (`0xfbff`).
//! 3. There is no AUTH phase one and no verifier exchange: the client sends AUTH phase two directly
//!    ([`build_auth_phase_two_tcps_frame`]) with no user name, auth mode `LOGON` (never
//!    `WITH_PASSWORD`), no `AUTH_SESSKEY`/`AUTH_PASSWORD`/`AUTH_TOKEN`, only the four session pairs
//!    (plus the edition and connect string), and never resends. The server maps the certificate
//!    subject DN the TLS handshake proved to the externally identified user; its reply carries no
//!    `AUTH_SVR_RESPONSE`, so there is nothing to verify and no key is derived.
//!
//! No cryptography runs here. The private key never reaches this crate: the TLS layer below it
//! (the embedder's host) holds the client identity and performs the handshake.

use super::*;

// Network data types (network_services.pyx).
const NET_TYPE_STRING: u16 = 0;
const NET_TYPE_RAW: u16 = 1;
const NET_TYPE_UB1: u16 = 2;
const NET_TYPE_UB2: u16 = 3;
const NET_TYPE_VERSION: u16 = 5;
const NET_TYPE_STATUS: u16 = 6;

/// Network service numbers.
pub const NET_SERVICE_AUTH: u16 = 1;
pub const NET_SERVICE_ENCRYPTION: u16 = 2;
pub const NET_SERVICE_DATA_INTEGRITY: u16 = 3;
pub const NET_SERVICE_SUPERVISOR: u16 = 4;

const NET_AUTH_TYPE_CLIENT_SERVER: u16 = 0xe0e1;
/// The server's authentication service took the session (TCPS authentication is configured).
pub const NET_AUTH_STATUS_OK: u16 = 0xfaff;
/// The server does not use network authentication for this session.
pub const NET_AUTH_STATUS_DONT_USE_AUTH: u16 = 0xfbff;
const NET_AUTH_STATUS_NOT_REQUIRED: u16 = 0xfcff;
/// The supervisor status a server sends when it accepts the negotiation.
const NET_SUPERVISOR_STATUS_OK: u16 = 0x001f;
const NET_MAGIC: u32 = 0xdead_beef;
/// The network-services version the reference advertises (23.7.0.0.0).
const NET_VERSION: u32 = 0x1770_0000;
/// The TCPS authentication adapter id and name.
const NET_AUTH_ID_TCPS: u8 = 2;
const NET_AUTH_NAME_TCPS: &[u8] = b"tcps";

/// The exact length of the TCPS-authentication network-services packet: the 13-byte header, then
/// supervisor 50, authentication 41, encryption 21 and data integrity 21.
pub const NETWORK_SERVICES_TCPS_AUTH_LEN: usize = 13 + 50 + 41 + 21 + 21;

/// The network-services (ANO) negotiation a TCPS-authenticated client sends after ACCEPT, as the
/// payload of one DATA packet (data flags 0). `connection_id` is the supervisor CID (the reference
/// sends the first 8 bytes of its random 16-byte connection id); the server treats it as an opaque
/// trace tag.
pub fn build_network_services_tcps_auth(connection_id: &[u8; 8]) -> Vec<u8> {
    let mut w = TtcWriter::with_capacity(NETWORK_SERVICES_TCPS_AUTH_LEN);
    // Header: magic, packet length, version, service count, flags.
    w.write_u32be(NET_MAGIC);
    w.write_u16be(NETWORK_SERVICES_TCPS_AUTH_LEN as u16);
    w.write_u32be(NET_VERSION);
    w.write_u16be(4);
    w.write_u8(0);

    // Supervisor: version, CID, the supervised services array.
    service_header(&mut w, NET_SERVICE_SUPERVISOR, 3);
    version(&mut w);
    w.write_u16be(8);
    w.write_u16be(NET_TYPE_RAW);
    w.write_raw(connection_id);
    w.write_u16be(18);
    w.write_u16be(NET_TYPE_RAW);
    w.write_u32be(NET_MAGIC);
    w.write_u16be(NET_TYPE_UB2);
    w.write_u32be(4);
    for service in [
        NET_SERVICE_SUPERVISOR,
        NET_SERVICE_AUTH,
        NET_SERVICE_ENCRYPTION,
        NET_SERVICE_DATA_INTEGRITY,
    ] {
        w.write_u16be(service);
    }

    // Authentication: version, type, status, the adapter id and name (TCPS only).
    service_header(&mut w, NET_SERVICE_AUTH, 5);
    version(&mut w);
    w.write_u16be(2);
    w.write_u16be(NET_TYPE_UB2);
    w.write_u16be(NET_AUTH_TYPE_CLIENT_SERVER);
    w.write_u16be(2);
    w.write_u16be(NET_TYPE_STATUS);
    w.write_u16be(NET_AUTH_STATUS_NOT_REQUIRED);
    w.write_u16be(1);
    w.write_u16be(NET_TYPE_UB1);
    w.write_u8(NET_AUTH_ID_TCPS);
    w.write_u16be(NET_AUTH_NAME_TCPS.len() as u16);
    w.write_u16be(NET_TYPE_STRING);
    w.write_raw(NET_AUTH_NAME_TCPS);

    // Encryption and data integrity: version, then one algorithm, 0 = none. The TLS session below
    // already protects the stream; native network encryption is never offered.
    for service in [NET_SERVICE_ENCRYPTION, NET_SERVICE_DATA_INTEGRITY] {
        service_header(&mut w, service, 2);
        version(&mut w);
        w.write_u16be(1);
        w.write_u16be(NET_TYPE_RAW);
        w.write_u8(0);
    }
    let bytes = w.into_bytes();
    debug_assert_eq!(bytes.len(), NETWORK_SERVICES_TCPS_AUTH_LEN);
    bytes
}

fn service_header(w: &mut TtcWriter, service: u16, sub_packets: u16) {
    w.write_u16be(service);
    w.write_u16be(sub_packets);
    w.write_u32be(0);
}

fn version(w: &mut TtcWriter) {
    w.write_u16be(4);
    w.write_u16be(NET_TYPE_VERSION);
    w.write_u32be(NET_VERSION);
}

/// What the server answered to [`build_network_services_tcps_auth`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetworkServicesReply {
    /// The server's authentication service took the session ([`NET_AUTH_STATUS_OK`]): it will map
    /// the client certificate to an externally identified user. `false` is
    /// [`NET_AUTH_STATUS_DONT_USE_AUTH`]: the server is not configured for TCPS authentication.
    pub tcps_authentication: bool,
    /// The authentication status word the server sent, when it sent an authentication service.
    pub auth_status: Option<u16>,
}

/// Bounds-checked big-endian reads over the reply.
struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(ProtocolError::TtcDecode("truncated network services reply"))?;
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// The status word of a status sub-packet (`len 2, type STATUS`).
fn status_of(sub: Option<&(u16, &[u8])>) -> Result<u16> {
    match sub {
        Some((NET_TYPE_STATUS, [hi, lo])) => Ok(u16::from_be_bytes([*hi, *lo])),
        _ => Err(ProtocolError::TtcDecode(
            "network service reply has no status sub-packet",
        )),
    }
}

/// Parse the server's network-services reply (the DATA payload after the data flags). A service
/// carrying a non-zero error is the listener refusing the connection; a supervisor or
/// authentication status other than the reference's accepted ones is a negotiation failure
/// (reference `ERR_ANO_STATUS_FAILURE`). Encryption and data integrity answers are read and
/// skipped: this client offered none.
pub fn parse_network_services_reply(payload: &[u8]) -> Result<NetworkServicesReply> {
    let mut c = Cursor {
        bytes: payload,
        at: 0,
    };
    if c.u32()? != NET_MAGIC {
        return Err(ProtocolError::TtcDecode(
            "network services reply has no ANO magic",
        ));
    }
    let _length = c.u16()?;
    let _version = c.u32()?;
    let services = c.u16()?;
    let _flags = c.take(1)?;
    let mut reply = NetworkServicesReply::default();
    for _ in 0..services {
        let service = c.u16()?;
        let sub_packets = c.u16()?;
        let error = c.u32()?;
        if error != 0 {
            return Err(ProtocolError::ServerError(format!(
                "the listener refused network service {service} (error {error})"
            )));
        }
        let mut subs: Vec<(u16, &[u8])> = Vec::with_capacity(usize::from(sub_packets.min(16)));
        for _ in 0..sub_packets {
            let len = usize::from(c.u16()?);
            let kind = c.u16()?;
            subs.push((kind, c.take(len)?));
        }
        match service {
            NET_SERVICE_SUPERVISOR => {
                if status_of(subs.get(1))? != NET_SUPERVISOR_STATUS_OK {
                    return Err(ProtocolError::ServerError(
                        "the server refused the network services negotiation (supervisor)".into(),
                    ));
                }
            }
            NET_SERVICE_AUTH => {
                let status = status_of(subs.get(1))?;
                reply.auth_status = Some(status);
                match status {
                    NET_AUTH_STATUS_OK => reply.tcps_authentication = true,
                    NET_AUTH_STATUS_DONT_USE_AUTH => reply.tcps_authentication = false,
                    _ => {
                        return Err(ProtocolError::ServerError(format!(
                            "the server refused the network services negotiation (authentication status {status:#06x})"
                        )))
                    }
                }
            }
            _ => {}
        }
    }
    Ok(reply)
}

/// AUTH phase two of a TCPS-authenticated session written onto `writer`: no user, auth mode
/// `LOGON`, the four session pairs, then the optional edition and the connect string (reference
/// messages/auth.pyx `_write_message` with `externalauth` and no token).
pub(crate) fn write_auth_phase_two_tcps(
    writer: &mut TtcWriter,
    driver_name: &str,
    version_num: u32,
    connect_string: &str,
    edition: Option<&str>,
) -> Result<()> {
    writer.write_function_code(TNS_FUNC_AUTH_PHASE_TWO);
    let mut num_pairs = 4u32;
    if edition.is_some() {
        num_pairs += 1;
    }
    if !connect_string.is_empty() {
        num_pairs += 1;
    }
    super::auth::write_auth_header(writer, "", TNS_AUTH_MODE_LOGON, num_pairs)?;
    super::auth::write_key_value(writer, "SESSION_CLIENT_CHARSET", "873", 0)?;
    super::auth::write_key_value(writer, "SESSION_CLIENT_DRIVER_NAME", driver_name, 0)?;
    super::auth::write_key_value(
        writer,
        "SESSION_CLIENT_VERSION",
        &version_num.to_string(),
        0,
    )?;
    super::auth::write_key_value(
        writer,
        "AUTH_ALTER_SESSION",
        "ALTER SESSION SET TIME_ZONE='+00:00'\0",
        1,
    )?;
    if let Some(edition) = edition {
        super::auth::write_key_value(writer, "AUTH_ORA_EDITION", edition, 0)?;
    }
    if !connect_string.is_empty() {
        super::auth::write_key_value(writer, "AUTH_CONNECT_STRING", connect_string, 0)?;
    }
    Ok(())
}

/// The TCPS-authentication phase-two frame: the fast-auth bundle (protocol negotiation, data types
/// and this message in one round trip) when `fast_auth`, else the standalone classic message sent
/// after the protocol and data-types round trips. Written once into a buffer of its exact length,
/// like the token frame ([`super::build_auth_phase_two_token_frame`]); it carries no credential.
pub fn build_auth_phase_two_tcps_frame(
    fast_auth: bool,
    driver_name: &str,
    version_num: u32,
    connect_string: &str,
    edition: Option<&str>,
) -> Result<Vec<u8>> {
    let prefix = if fast_auth {
        Vec::from_hex(FAST_AUTH_PREFIX_HEX)
            .map_err(|_| ProtocolError::TtcDecode("invalid static fast-auth prefix"))?
    } else {
        Vec::new()
    };
    let mut measure = TtcWriter::new();
    write_auth_phase_two_tcps(
        &mut measure,
        driver_name,
        version_num,
        connect_string,
        edition,
    )?;
    let capacity = prefix.len() + measure.into_bytes().len();
    let mut writer = TtcWriter::with_capacity(capacity);
    writer.write_raw(&prefix);
    write_auth_phase_two_tcps(
        &mut writer,
        driver_name,
        version_num,
        connect_string,
        edition,
    )?;
    let frame = writer.into_bytes();
    if frame.len() != capacity {
        return Err(ProtocolError::TtcDecode(
            "TCPS auth frame length changed while writing",
        ));
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CID: [u8; 8] = *b"BUSBARv1";
    const CONNECT: &str =
        "(DESCRIPTION=(ADDRESS=(PROTOCOL=tcps)(HOST=h)(PORT=2484))(CONNECT_DATA=(SERVICE_NAME=S)))";

    fn hex(text: &str) -> Vec<u8> {
        let clean: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        Vec::from_hex(clean).unwrap()
    }

    /// The network-services packet, byte for byte as the reference writes it
    /// (network_services.pyx `NetworkServicesMessage._write_message` with no TLS wrapper and not
    /// in negotiation: Supervisor, Authentication, Encryption, DataIntegrity).
    #[test]
    fn network_services_packet_matches_the_reference_bytes() {
        let expected = hex(concat!(
            // header: magic, length 146, version 23.7, 4 services, flags 0
            "deadbeef 0092 17700000 0004 00",
            // supervisor: service 4, 3 sub-packets, error 0
            "0004 0003 00000000",
            "0004 0005 17700000",
            "0008 0001 4255534241527631", // CID "BUSBARv1"
            "0012 0001 deadbeef 0003 00000004 0004 0001 0002 0003",
            // authentication: service 1, 5 sub-packets
            "0001 0005 00000000",
            "0004 0005 17700000",
            "0002 0003 e0e1",     // client/server auth type
            "0002 0006 fcff",     // status: not required
            "0001 0002 02",       // adapter id 2 (TCPS)
            "0004 0000 74637073", // adapter name "tcps"
            // encryption: service 2, 2 sub-packets, no algorithm
            "0002 0002 00000000",
            "0004 0005 17700000",
            "0001 0001 00",
            // data integrity: service 3, 2 sub-packets, no algorithm
            "0003 0002 00000000",
            "0004 0005 17700000",
            "0001 0001 00",
        ));
        let built = build_network_services_tcps_auth(&CID);
        assert_eq!(built, expected);
        assert_eq!(built.len(), NETWORK_SERVICES_TCPS_AUTH_LEN);
        assert_eq!(built.capacity(), built.len(), "written at its exact length");
    }

    /// CONNECT for TCPS authentication differs from the ordinary one only in the two NSI flag bytes
    /// (offsets 24 and 25 of the payload): NA stays enabled (0x80, not 0x84).
    #[test]
    fn tcps_connect_leaves_network_authentication_enabled() {
        let plain = build_connect_packet_payload(CONNECT, 8192).unwrap();
        let tcps = build_connect_packet_payload_tcps_auth(CONNECT, 8192).unwrap();
        assert_eq!(plain.len(), tcps.len());
        assert_eq!(&plain[24..26], &[0x84, 0x84]);
        assert_eq!(&tcps[24..26], &[0x80, 0x80]);
        let differing: Vec<usize> = (0..plain.len()).filter(|i| plain[*i] != tcps[*i]).collect();
        assert_eq!(differing, vec![24, 25]);
    }

    /// One key/value pair as the reference writes it (messages/auth.pyx `_write_key_value`:
    /// `write_bytes_with_two_lengths` of key and value, then `ub4 flags`), for short strings.
    fn kv(out: &mut Vec<u8>, key: &str, value: &str, flags: u8) {
        for text in [key, value] {
            let len = u8::try_from(text.len()).unwrap();
            out.extend_from_slice(&[1, len, len]);
            out.extend_from_slice(text.as_bytes());
        }
        if flags == 0 {
            out.push(0);
        } else {
            out.extend_from_slice(&[1, flags]);
        }
    }

    /// The classic phase-two message, independently assembled from the reference layout: function
    /// header (msg type 3, function 0x73, seq 1), `has_user` 0, user length 0, mode `LOGON`,
    /// `authivl` 1, the pair count, `authovl` 1, `authovln` 1, no user bytes, then the pairs.
    fn reference_phase_two(edition: Option<&str>, connect: &str) -> Vec<u8> {
        let pairs = 4 + u8::from(edition.is_some()) + u8::from(!connect.is_empty());
        let mut out = vec![
            TNS_MSG_TYPE_FUNCTION,
            TNS_FUNC_AUTH_PHASE_TWO,
            1,
            0,
            0,
            1,
            1,
            1,
            1,
            pairs,
            1,
            1,
        ];
        kv(&mut out, "SESSION_CLIENT_CHARSET", "873", 0);
        kv(
            &mut out,
            "SESSION_CLIENT_DRIVER_NAME",
            "busbar-store-oracle",
            0,
        );
        kv(&mut out, "SESSION_CLIENT_VERSION", "67112960", 0);
        kv(
            &mut out,
            "AUTH_ALTER_SESSION",
            "ALTER SESSION SET TIME_ZONE='+00:00'\0",
            1,
        );
        if let Some(edition) = edition {
            kv(&mut out, "AUTH_ORA_EDITION", edition, 0);
        }
        if !connect.is_empty() {
            kv(&mut out, "AUTH_CONNECT_STRING", connect, 0);
        }
        out
    }

    #[test]
    fn phase_two_matches_the_reference_layout_byte_for_byte() {
        for (edition, connect) in [
            (None, CONNECT),
            (None, ""),
            (Some("E_TEST"), CONNECT),
            (Some("E_TEST"), ""),
        ] {
            let built = build_auth_phase_two_tcps_frame(
                false,
                "busbar-store-oracle",
                0x0400_1000,
                connect,
                edition,
            )
            .unwrap();
            assert_eq!(
                built,
                reference_phase_two(edition, connect),
                "edition={edition:?} connect={}",
                !connect.is_empty()
            );
            assert_eq!(built.capacity(), built.len());
        }
    }

    #[test]
    fn fast_auth_frame_is_the_static_bundle_then_the_same_message() {
        let prefix = Vec::from_hex(FAST_AUTH_PREFIX_HEX).unwrap();
        let built = build_auth_phase_two_tcps_frame(
            true,
            "busbar-store-oracle",
            0x0400_1000,
            CONNECT,
            None,
        )
        .unwrap();
        assert_eq!(&built[..prefix.len()], &prefix[..]);
        assert_eq!(
            &built[prefix.len()..],
            &reference_phase_two(None, CONNECT)[..]
        );
        assert_eq!(built.capacity(), built.len());
    }

    /// No credential of any kind is in the TCPS frame: the certificate already authenticated.
    #[test]
    fn phase_two_carries_no_credential_and_no_user() {
        let built = build_auth_phase_two_tcps_frame(false, "busbar-store-oracle", 1, CONNECT, None)
            .unwrap();
        for needle in [
            &b"AUTH_SESSKEY"[..],
            b"AUTH_PASSWORD",
            b"AUTH_PBKDF2_SPEEDY_KEY",
            b"AUTH_TOKEN",
            b"AUTH_HEADER",
            b"PROXY_CLIENT_NAME",
        ] {
            assert!(
                !built.windows(needle.len()).any(|w| w == needle),
                "{}",
                String::from_utf8_lossy(needle)
            );
        }
        assert_eq!(built[3], 0, "has_user is 0");
    }

    /// A server reply the way the reference reads it (network_services.pyx `process` and each
    /// service's `read_subpackets`).
    fn reply(auth_status: u16, supervisor_status: u16, auth_error: u32) -> Vec<u8> {
        let mut r = hex("deadbeef 0000 17700000 0004 00");
        // supervisor: version, status, services array
        r.extend(hex("0004 0003 00000000 0004 0005 17700000"));
        r.extend(hex("0002 0006"));
        r.extend(supervisor_status.to_be_bytes());
        r.extend(hex("0012 0001 deadbeef 0003 00000004 0004 0001 0002 0003"));
        // authentication: version, status, and (when OK) the chosen adapter id and name
        let ok = auth_status == NET_AUTH_STATUS_OK;
        r.extend(hex("0001"));
        r.extend(if ok { hex("0004") } else { hex("0002") });
        r.extend(auth_error.to_be_bytes());
        r.extend(hex("0004 0005 17700000 0002 0006"));
        r.extend(auth_status.to_be_bytes());
        if ok {
            r.extend(hex("0001 0002 02 0004 0000 74637073"));
        }
        // encryption and data integrity: version and the chosen algorithm (none)
        r.extend(hex("0002 0002 00000000 0004 0005 17700000 0001 0002 00"));
        r.extend(hex("0003 0002 00000000 0004 0005 17700000 0001 0002 00"));
        r
    }

    #[test]
    fn reply_with_tcps_authentication_taken() {
        let parsed = parse_network_services_reply(&reply(NET_AUTH_STATUS_OK, 0x1f, 0)).unwrap();
        assert!(parsed.tcps_authentication);
        assert_eq!(parsed.auth_status, Some(NET_AUTH_STATUS_OK));
    }

    #[test]
    fn reply_without_network_authentication() {
        let parsed =
            parse_network_services_reply(&reply(NET_AUTH_STATUS_DONT_USE_AUTH, 0x1f, 0)).unwrap();
        assert!(!parsed.tcps_authentication);
        assert_eq!(parsed.auth_status, Some(NET_AUTH_STATUS_DONT_USE_AUTH));
    }

    #[test]
    fn refusals_and_malformed_replies_are_errors() {
        // An authentication status the reference does not accept.
        let e = parse_network_services_reply(&reply(0xfcff, 0x1f, 0)).unwrap_err();
        assert!(
            matches!(e, ProtocolError::ServerError(ref t) if t.contains("0xfcff")),
            "{e:?}"
        );
        // A supervisor that did not accept the negotiation.
        let e = parse_network_services_reply(&reply(NET_AUTH_STATUS_OK, 0x0, 0)).unwrap_err();
        assert!(
            matches!(e, ProtocolError::ServerError(ref t) if t.contains("supervisor")),
            "{e:?}"
        );
        // A service error (the listener refusing, e.g. ORA-12650).
        let e = parse_network_services_reply(&reply(NET_AUTH_STATUS_OK, 0x1f, 12650)).unwrap_err();
        assert!(
            matches!(e, ProtocolError::ServerError(ref t) if t.contains("12650")),
            "{e:?}"
        );
        // Not an ANO reply, and every truncation.
        assert!(parse_network_services_reply(&hex("00000000 0000")).is_err());
        let whole = reply(NET_AUTH_STATUS_OK, 0x1f, 0);
        for cut in 0..whole.len() {
            assert!(
                parse_network_services_reply(&whole[..cut]).is_err(),
                "cut {cut}"
            );
        }
    }
}
