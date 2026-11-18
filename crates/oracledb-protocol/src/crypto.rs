#![forbid(unsafe_code)]
//! O5LOGON (the 12c password verifier exchange) over a caller-supplied crypto provider.
//!
//! Every primitive the exchange needs goes through [`O5Crypto`]: a DRBG, SHA-512,
//! PBKDF2-HMAC-SHA512 and unpadded AES-256-CBC. Each is a standard primitive with no Oracle
//! shape; the protocol (the `AUTH_PBKDF2_SPEEDY_KEY` salt suffix, the zero IV, the value padding,
//! the truncations and the hex re-encoding) stays in this module. An embedder whose host owns a
//! validated crypto module implements the trait over that module and builds this crate with
//! `default-features = false`, so no second implementation is linked. [`RustCrypto`] (feature
//! `o5logon-rustcrypto`, default-on) is the in-crate implementation.
//!
//! Only the 12C verifier is supported. The pre-12c combo key (MD5 over the key parts, taken when
//! the server's session key is 48 bytes) is refused unconditionally with
//! [`ProtocolError::LegacySessionKey`], before any digest is computed.

use std::collections::BTreeMap;

use hex::FromHex;

use crate::thin::TNS_VERIFIER_TYPE_12C;
use crate::{ProtocolError, Result};

/// The zero IV every O5LOGON CBC operation uses. Each encrypt starts with a fresh random block
/// (the 32-byte client key part or a 16-byte salt), so the later blocks see an unpredictable IV.
const ZERO_IV: [u8; 16] = [0; 16];
/// The AES-256 key, the 12c password hash and the combo key are all this long.
const KEY_LEN: usize = 32;
/// The pre-12c (AES-192) session key part: the length that selects the MD5 combo key.
const LEGACY_SESSION_KEY_LEN: usize = 48;

/// The primitives O5LOGON runs on. Implementations must not add or strip padding, and must
/// answer a refusal of the parameters (a validated module's policy) with
/// [`ProtocolError::CryptoUnavailable`] and a malfunction with [`ProtocolError::CryptoFailed`].
pub trait O5Crypto {
    /// Fill `out` from an approved random source.
    fn random(&self, out: &mut [u8]) -> Result<()>;
    /// SHA-512 of `data`.
    fn sha512(&self, data: &[u8]) -> Result<[u8; 64]>;
    /// PBKDF2-HMAC-SHA512 (RFC 8018) of `password` and `salt` over `iterations` into `out`
    /// (1..=64 bytes: one PRF block).
    fn pbkdf2_hmac_sha512(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8],
    ) -> Result<()>;
    /// AES-CBC encryption (SP 800-38A), no padding: `key` is 32 bytes, `data` a non-empty
    /// multiple of 16 bytes; the answer is as long as `data`.
    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>>;
    /// The inverse of [`O5Crypto::aes_cbc_encrypt`]; no padding is removed.
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>>;
}

impl<T: O5Crypto + ?Sized> O5Crypto for &T {
    fn random(&self, out: &mut [u8]) -> Result<()> {
        (**self).random(out)
    }
    fn sha512(&self, data: &[u8]) -> Result<[u8; 64]> {
        (**self).sha512(data)
    }
    fn pbkdf2_hmac_sha512(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out: &mut [u8],
    ) -> Result<()> {
        (**self).pbkdf2_hmac_sha512(password, salt, iterations, out)
    }
    fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        (**self).aes_cbc_encrypt(key, iv, data)
    }
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
        (**self).aes_cbc_decrypt(key, iv, data)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPassword {
    pub session_key: String,
    pub speedy_key: Option<String>,
    pub password: String,
    pub combo_key: Vec<u8>,
}

/// The phase-two verifier material for `password` against the server's phase-one
/// `session_data`, computed over `crypto`. Only [`TNS_VERIFIER_TYPE_12C`] is accepted.
pub fn generate_verifier_with(
    crypto: &impl O5Crypto,
    password: &[u8],
    session_data: &BTreeMap<String, String>,
    verifier_type: u32,
) -> Result<EncryptedPassword> {
    if verifier_type != TNS_VERIFIER_TYPE_12C {
        // The 10G/11G verifiers hash the password with SHA-1 and need AES-192 session keys
        // with the MD5 combo key: neither is offered.
        return Err(ProtocolError::UnsupportedVerifier { verifier_type });
    }
    let verifier_data = decode_session_hex(session_data, "AUTH_VFR_DATA")?;
    let iterations = parse_session_u32(session_data, "AUTH_PBKDF2_VGEN_COUNT")?;
    let mut salt = verifier_data.clone();
    salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
    let mut password_key = [0u8; 64];
    crypto.pbkdf2_hmac_sha512(password, &salt, iterations, &mut password_key)?;
    let mut hashed = password_key.to_vec();
    hashed.extend_from_slice(&verifier_data);
    let digest = crypto.sha512(&hashed);
    hashed.fill(0);
    let password_hash = digest?;
    let password_hash = &password_hash[..KEY_LEN];

    let encoded_server_key = decode_session_hex(session_data, "AUTH_SESSKEY")?;
    if encoded_server_key.is_empty() || !encoded_server_key.len().is_multiple_of(16) {
        return Err(ProtocolError::TtcDecode(
            "AES-CBC ciphertext length is not block aligned",
        ));
    }
    let session_key_part_a =
        crypto.aes_cbc_decrypt(password_hash, &ZERO_IV, &encoded_server_key)?;
    if session_key_part_a.len() == LEGACY_SESSION_KEY_LEN {
        return Err(ProtocolError::LegacySessionKey);
    }
    if session_key_part_a.len() < KEY_LEN {
        return Err(ProtocolError::TtcDecode("session key too short"));
    }
    let mut session_key_part_b = vec![0u8; session_key_part_a.len()];
    crypto.random(&mut session_key_part_b)?;
    // CBC is prefix-preserving: the unpadded encryption of the aligned part B is exactly the
    // prefix the protocol keeps of its padded encryption (64 hex characters).
    let encoded_client_key =
        crypto.aes_cbc_encrypt(password_hash, &ZERO_IV, &session_key_part_b)?;
    let session_key = hex_upper_truncated(&encoded_client_key, 2 * KEY_LEN);

    let csk_salt = decode_session_hex(session_data, "AUTH_PBKDF2_CSK_SALT")?;
    let sder_iterations = parse_session_u32(session_data, "AUTH_PBKDF2_SDER_COUNT")?;
    let mut temp_key = session_key_part_b[..KEY_LEN].to_vec();
    temp_key.extend_from_slice(&session_key_part_a[..KEY_LEN]);
    let temp_key_hex = hex_upper(&temp_key);
    temp_key.fill(0);
    session_key_part_b.fill(0);
    let mut combo_key = vec![0u8; KEY_LEN];
    crypto.pbkdf2_hmac_sha512(
        temp_key_hex.as_bytes(),
        &csk_salt,
        sder_iterations,
        &mut combo_key,
    )?;

    // The speedy key: a random salt then the 64-byte password key, 80 aligned bytes whose
    // unpadded encryption is the 160 hex characters the protocol keeps.
    let mut speedy_plain = vec![0u8; 16];
    crypto.random(&mut speedy_plain)?;
    speedy_plain.extend_from_slice(&password_key);
    password_key.fill(0);
    let speedy = crypto.aes_cbc_encrypt(&combo_key, &ZERO_IV, &speedy_plain);
    speedy_plain.fill(0);
    let speedy_key = hex_upper(&speedy?);

    let encrypted_password = encrypt_salted(crypto, &combo_key, password)?;
    Ok(EncryptedPassword {
        session_key,
        speedy_key: Some(speedy_key),
        password: hex_upper(&encrypted_password),
        combo_key,
    })
}

/// Encrypt the old/new password pair with the session combo key for the change-password call
/// (reference messages/auth.pyx `_encrypt_passwords`: one shared random salt, AES-CBC under
/// `_combo_key`, upper-hex encoding).
pub fn encrypt_change_password_pair_with(
    crypto: &impl O5Crypto,
    combo_key: &[u8],
    old_password: &[u8],
    new_password: &[u8],
) -> Result<(String, String)> {
    let mut salt = [0u8; 16];
    crypto.random(&mut salt)?;
    let encrypted_old = encrypt_with_salt(crypto, combo_key, &salt, old_password)?;
    let encrypted_new = encrypt_with_salt(crypto, combo_key, &salt, new_password)?;
    Ok((hex_upper(&encrypted_old), hex_upper(&encrypted_new)))
}

/// Check the server's proof: `AUTH_SVR_RESPONSE` decrypts under the combo key to a block whose
/// bytes 16..32 are `SERVER_TO_CLIENT` (compared in constant time).
pub fn verify_server_response_with(
    crypto: &impl O5Crypto,
    combo_key: &[u8],
    session_data: &BTreeMap<String, String>,
) -> Result<()> {
    let Some(response_hex) = session_data.get("AUTH_SVR_RESPONSE") else {
        return Err(ProtocolError::InvalidServerResponse);
    };
    let encoded_response =
        Vec::from_hex(response_hex).map_err(|_| ProtocolError::InvalidServerResponse)?;
    if encoded_response.len() < 32 || !encoded_response.len().is_multiple_of(16) {
        return Err(ProtocolError::InvalidServerResponse);
    }
    let response = crypto.aes_cbc_decrypt(combo_key, &ZERO_IV, &encoded_response)?;
    match response.get(16..32) {
        Some(marker) if ct_eq(marker, b"SERVER_TO_CLIENT") => Ok(()),
        _ => Err(ProtocolError::InvalidServerResponse),
    }
}

/// `salt(16 random) || text`, value-padded (a whole block when aligned), encrypted unpadded.
fn encrypt_salted(crypto: &impl O5Crypto, key: &[u8], text: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    crypto.random(&mut salt)?;
    encrypt_with_salt(crypto, key, &salt, text)
}

fn encrypt_with_salt(
    crypto: &impl O5Crypto,
    key: &[u8],
    salt: &[u8; 16],
    text: &[u8],
) -> Result<Vec<u8>> {
    let mut plain = salt.to_vec();
    plain.extend_from_slice(text);
    let pad = 16 - plain.len() % 16;
    plain.extend(std::iter::repeat_n(pad as u8, pad));
    let out = crypto.aes_cbc_encrypt(key, &ZERO_IV, &plain);
    plain.fill(0);
    out
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn decode_session_hex(
    session_data: &BTreeMap<String, String>,
    key: &'static str,
) -> Result<Vec<u8>> {
    let value = session_data
        .get(key)
        .ok_or(ProtocolError::MissingAuthParameter { key })?;
    Vec::from_hex(value).map_err(|_| ProtocolError::MissingAuthParameter { key })
}

fn parse_session_u32(session_data: &BTreeMap<String, String>, key: &'static str) -> Result<u32> {
    session_data
        .get(key)
        .ok_or(ProtocolError::MissingAuthParameter { key })?
        .parse()
        .map_err(|_| ProtocolError::MissingAuthParameter { key })
}

fn hex_upper(bytes: &[u8]) -> String {
    hex::encode_upper(bytes)
}

fn hex_upper_truncated(bytes: &[u8], chars: usize) -> String {
    let mut text = hex_upper(bytes);
    text.truncate(chars);
    text
}

#[cfg(feature = "o5logon-rustcrypto")]
pub use rustcrypto::{
    encrypt_change_password_pair, generate_verifier, verify_server_response, RustCrypto,
};

#[cfg(feature = "o5logon-rustcrypto")]
mod rustcrypto {
    use std::collections::BTreeMap;

    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha512};

    use super::{EncryptedPassword, O5Crypto};
    use crate::{ProtocolError, Result};

    /// [`O5Crypto`] over the RustCrypto crates (`pbkdf2`, `sha2`, `aes`) and the OS RNG.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RustCrypto;

    fn aligned(data: &[u8]) -> Result<()> {
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(ProtocolError::TtcDecode(
                "AES-CBC data length is not block aligned",
            ));
        }
        Ok(())
    }

    impl O5Crypto for RustCrypto {
        fn random(&self, out: &mut [u8]) -> Result<()> {
            OsRng
                .try_fill_bytes(out)
                .map_err(|_| ProtocolError::CryptoFailed {
                    operation: "random",
                })
        }

        fn sha512(&self, data: &[u8]) -> Result<[u8; 64]> {
            let digest = Sha512::digest(data);
            let mut out = [0u8; 64];
            out.copy_from_slice(&digest);
            Ok(out)
        }

        fn pbkdf2_hmac_sha512(
            &self,
            password: &[u8],
            salt: &[u8],
            iterations: u32,
            out: &mut [u8],
        ) -> Result<()> {
            if iterations == 0 || out.is_empty() || out.len() > 64 {
                return Err(ProtocolError::CryptoUnavailable {
                    operation: "PBKDF2-HMAC-SHA512",
                });
            }
            pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, out);
            Ok(())
        }

        fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
            aligned(data)?;
            let cipher = Aes256::new_from_slice(key).map_err(|_| ProtocolError::InvalidAesKey)?;
            let mut out = data.to_vec();
            let mut previous = *iv;
            for block in out.chunks_mut(16) {
                for (byte, prev) in block.iter_mut().zip(previous) {
                    *byte ^= prev;
                }
                let block_ref = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
                cipher.encrypt_block(block_ref);
                previous.copy_from_slice(block_ref);
            }
            Ok(out)
        }

        fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
            aligned(data)?;
            let cipher = Aes256::new_from_slice(key).map_err(|_| ProtocolError::InvalidAesKey)?;
            let mut out = data.to_vec();
            let mut previous = *iv;
            for block in out.chunks_mut(16) {
                let current: [u8; 16] = block
                    .try_into()
                    .map_err(|_| ProtocolError::TtcDecode("invalid AES block"))?;
                let block_ref = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
                cipher.decrypt_block(block_ref);
                for (byte, prev) in block.iter_mut().zip(previous) {
                    *byte ^= prev;
                }
                previous = current;
            }
            Ok(out)
        }
    }

    /// [`super::generate_verifier_with`] over [`RustCrypto`].
    pub fn generate_verifier(
        password: &[u8],
        session_data: &BTreeMap<String, String>,
        verifier_type: u32,
    ) -> Result<EncryptedPassword> {
        super::generate_verifier_with(&RustCrypto, password, session_data, verifier_type)
    }

    /// [`super::encrypt_change_password_pair_with`] over [`RustCrypto`].
    pub fn encrypt_change_password_pair(
        combo_key: &[u8],
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<(String, String)> {
        super::encrypt_change_password_pair_with(&RustCrypto, combo_key, old_password, new_password)
    }

    /// [`super::verify_server_response_with`] over [`RustCrypto`].
    pub fn verify_server_response(
        combo_key: &[u8],
        session_data: &BTreeMap<String, String>,
    ) -> Result<()> {
        super::verify_server_response_with(&RustCrypto, combo_key, session_data)
    }
}

#[cfg(all(test, feature = "o5logon-rustcrypto"))]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Every error variant this file can raise is server-response-driven: a hostile or buggy
    // listener controls `session_data`, so a missing or malformed AUTH_* key must fail closed
    // with the right typed error, never panic.

    fn unhex(text: &str) -> Vec<u8> {
        Vec::from_hex(text.replace(' ', "")).unwrap()
    }

    /// RustCrypto that counts its calls (and can replay fixed random bytes).
    #[derive(Default)]
    struct Counting {
        random: Cell<usize>,
        sha512: Cell<usize>,
        pbkdf2: Cell<usize>,
    }

    impl O5Crypto for Counting {
        fn random(&self, out: &mut [u8]) -> Result<()> {
            self.random.set(self.random.get() + 1);
            RustCrypto.random(out)
        }
        fn sha512(&self, data: &[u8]) -> Result<[u8; 64]> {
            self.sha512.set(self.sha512.get() + 1);
            RustCrypto.sha512(data)
        }
        fn pbkdf2_hmac_sha512(
            &self,
            password: &[u8],
            salt: &[u8],
            iterations: u32,
            out: &mut [u8],
        ) -> Result<()> {
            self.pbkdf2.set(self.pbkdf2.get() + 1);
            RustCrypto.pbkdf2_hmac_sha512(password, salt, iterations, out)
        }
        fn aes_cbc_encrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
            RustCrypto.aes_cbc_encrypt(key, iv, data)
        }
        fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8; 16], data: &[u8]) -> Result<Vec<u8>> {
            RustCrypto.aes_cbc_decrypt(key, iv, data)
        }
    }

    #[test]
    fn rustcrypto_cbc_matches_sp800_38a_f2_5_and_f2_6() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let plain = unhex(
            "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51 \
             30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710",
        );
        let cipher = unhex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6 9cfc4e967edb808d679f777bc6702c7d \
             39f23369a9d9bacfa530e26304231461 b2eb05e2c39be9fcda6c19078c6a9d1b",
        );
        assert_eq!(
            RustCrypto.aes_cbc_encrypt(&key, &iv, &plain).unwrap(),
            cipher
        );
        assert_eq!(
            RustCrypto.aes_cbc_decrypt(&key, &iv, &cipher).unwrap(),
            plain
        );
        // No padding is added or stripped: the last block alone decrypts under IV = C3.
        let c3: [u8; 16] = cipher[32..48].try_into().unwrap();
        assert_eq!(
            RustCrypto
                .aes_cbc_decrypt(&key, &c3, &cipher[48..])
                .unwrap(),
            plain[48..]
        );
        for bad in [&plain[..15], &[][..]] {
            assert!(RustCrypto.aes_cbc_encrypt(&key, &iv, bad).is_err());
            assert!(RustCrypto.aes_cbc_decrypt(&key, &iv, bad).is_err());
        }
        assert!(matches!(
            RustCrypto.aes_cbc_encrypt(&key[..24], &iv, &plain),
            Err(ProtocolError::InvalidAesKey)
        ));
    }

    #[test]
    fn rustcrypto_pbkdf2_sha512_matches_the_known_answers() {
        let mut out = [0u8; 64];
        RustCrypto
            .pbkdf2_hmac_sha512(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                &mut out,
            )
            .unwrap();
        assert_eq!(
            out.to_vec(),
            unhex(
                "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71\
                 115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"
            )
        );
        let salt: Vec<u8> = (0u8..16).collect();
        RustCrypto
            .pbkdf2_hmac_sha512(b"correct horse battery staple", &salt, 1000, &mut out)
            .unwrap();
        let k5 = unhex(
            "03a026148b62ec22a561da0f895f637f577d965a77ee8dbb5a6b3c671f1fc0c2\
             4608e8a027302d84e5b73e0f971793e7362627b10b08cf537936dca7ac49bbf3",
        );
        assert_eq!(out.to_vec(), k5);
        let mut short = [0u8; 32];
        RustCrypto
            .pbkdf2_hmac_sha512(b"correct horse battery staple", &salt, 1000, &mut short)
            .unwrap();
        assert_eq!(short[..], k5[..32], "a shorter key is the prefix");
        for (iterations, len) in [(0, 64), (1, 0), (1, 65)] {
            let mut out = vec![0u8; len];
            assert!(matches!(
                RustCrypto.pbkdf2_hmac_sha512(b"p", b"s", iterations, &mut out),
                Err(ProtocolError::CryptoUnavailable { .. })
            ));
        }
    }

    /// The server's half of O5LOGON, written from the protocol: a 12c login of `password` with
    /// a 32-byte server key part.
    struct Server {
        session_data: BTreeMap<String, String>,
        password_hash: Vec<u8>,
        password_key: [u8; 64],
        part_a: Vec<u8>,
    }

    impl Server {
        fn new(password: &[u8], part_a_len: usize) -> Self {
            let vfr = unhex("8a5e3f0c1b2d4e6f7081920a1b2c3d4e");
            let mut salt = vfr.clone();
            salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
            let mut password_key = [0u8; 64];
            RustCrypto
                .pbkdf2_hmac_sha512(password, &salt, 4096, &mut password_key)
                .unwrap();
            let mut hashed = password_key.to_vec();
            hashed.extend_from_slice(&vfr);
            let password_hash = RustCrypto.sha512(&hashed).unwrap()[..32].to_vec();
            let part_a: Vec<u8> = (0..part_a_len).map(|i| (i * 7 + 3) as u8).collect();
            let sesskey = RustCrypto
                .aes_cbc_encrypt(&password_hash, &ZERO_IV, &part_a)
                .unwrap();
            let mut session_data = BTreeMap::new();
            for (k, v) in [
                ("AUTH_VFR_DATA", hex_upper(&vfr)),
                ("AUTH_PBKDF2_VGEN_COUNT", "4096".into()),
                ("AUTH_SESSKEY", hex_upper(&sesskey)),
                ("AUTH_PBKDF2_CSK_SALT", hex_upper(&[0x5a; 16])),
                ("AUTH_PBKDF2_SDER_COUNT", "3".into()),
            ] {
                session_data.insert(k.to_string(), v);
            }
            Self {
                session_data,
                password_hash,
                password_key,
                part_a,
            }
        }

        fn combo_key(&self, encrypted: &EncryptedPassword) -> Vec<u8> {
            let encoded = Vec::from_hex(&encrypted.session_key).unwrap();
            let part_b = RustCrypto
                .aes_cbc_decrypt(&self.password_hash, &ZERO_IV, &encoded)
                .unwrap();
            let mut temp = part_b[..32].to_vec();
            temp.extend_from_slice(&self.part_a[..32]);
            let mut combo = vec![0u8; 32];
            RustCrypto
                .pbkdf2_hmac_sha512(hex_upper(&temp).as_bytes(), &[0x5a; 16], 3, &mut combo)
                .unwrap();
            combo
        }
    }

    #[test]
    fn a_12c_login_round_trips_with_the_server() {
        let password = b"a-correct-password";
        let server = Server::new(password, 32);
        let encrypted =
            generate_verifier(password, &server.session_data, TNS_VERIFIER_TYPE_12C).unwrap();
        assert_eq!(encrypted.session_key.len(), 64);
        let combo = server.combo_key(&encrypted);
        assert_eq!(
            encrypted.combo_key, combo,
            "both sides derive one combo key"
        );
        // AUTH_PASSWORD: salt, then the password, value-padded.
        let sealed = Vec::from_hex(&encrypted.password).unwrap();
        let plain = RustCrypto
            .aes_cbc_decrypt(&combo, &ZERO_IV, &sealed)
            .unwrap();
        let pad = usize::from(*plain.last().unwrap());
        assert_eq!(&plain[16..plain.len() - pad], password);
        // AUTH_PBKDF2_SPEEDY_KEY: salt, then the 64-byte password key, 160 hex characters.
        let speedy = Vec::from_hex(encrypted.speedy_key.as_deref().unwrap()).unwrap();
        assert_eq!(speedy.len(), 80);
        let plain = RustCrypto
            .aes_cbc_decrypt(&combo, &ZERO_IV, &speedy)
            .unwrap();
        assert_eq!(plain[16..], server.password_key[..]);
        // The server's proof verifies; one made under another key does not.
        let mut proof = vec![0x11u8; 16];
        proof.extend_from_slice(b"SERVER_TO_CLIENT");
        let mut answer = BTreeMap::new();
        let sealed = RustCrypto
            .aes_cbc_encrypt(&combo, &ZERO_IV, &proof)
            .unwrap();
        answer.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&sealed));
        verify_server_response(&combo, &answer).unwrap();
        let forged = RustCrypto
            .aes_cbc_encrypt(&[9u8; 32], &ZERO_IV, &proof)
            .unwrap();
        answer.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&forged));
        assert!(matches!(
            verify_server_response(&combo, &answer),
            Err(ProtocolError::InvalidServerResponse)
        ));
    }

    #[test]
    fn the_pre_12c_md5_session_key_is_refused_before_any_key_is_drawn() {
        let server = Server::new(b"pw", 48);
        let crypto = Counting::default();
        let err =
            generate_verifier_with(&crypto, b"pw", &server.session_data, TNS_VERIFIER_TYPE_12C)
                .expect_err("a 48-byte session key part must be refused");
        assert!(
            matches!(err, ProtocolError::LegacySessionKey),
            "got {err:?}"
        );
        assert!(err.to_string().contains("MD5"));
        assert_eq!(crypto.random.get(), 0, "no client key part was drawn");
        assert_eq!(crypto.pbkdf2.get(), 1, "only the password key was derived");
    }

    #[test]
    fn a_provider_refusal_reaches_the_caller_typed() {
        struct Refusing;
        impl O5Crypto for Refusing {
            fn random(&self, out: &mut [u8]) -> Result<()> {
                RustCrypto.random(out)
            }
            fn sha512(&self, data: &[u8]) -> Result<[u8; 64]> {
                RustCrypto.sha512(data)
            }
            fn pbkdf2_hmac_sha512(&self, _: &[u8], _: &[u8], _: u32, _: &mut [u8]) -> Result<()> {
                Err(ProtocolError::CryptoUnavailable {
                    operation: "PBKDF2-HMAC-SHA512",
                })
            }
            fn aes_cbc_encrypt(&self, k: &[u8], iv: &[u8; 16], d: &[u8]) -> Result<Vec<u8>> {
                RustCrypto.aes_cbc_encrypt(k, iv, d)
            }
            fn aes_cbc_decrypt(&self, k: &[u8], iv: &[u8; 16], d: &[u8]) -> Result<Vec<u8>> {
                RustCrypto.aes_cbc_decrypt(k, iv, d)
            }
        }
        let server = Server::new(b"pw", 32);
        let err = generate_verifier_with(
            &Refusing,
            b"pw",
            &server.session_data,
            TNS_VERIFIER_TYPE_12C,
        )
        .unwrap_err();
        assert!(
            matches!(err, ProtocolError::CryptoUnavailable { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn generate_verifier_rejects_missing_auth_vfr_data() {
        let session_data = BTreeMap::new();
        let err = generate_verifier(b"password", &session_data, TNS_VERIFIER_TYPE_12C)
            .expect_err("missing AUTH_VFR_DATA must be rejected");
        assert!(
            matches!(
                err,
                ProtocolError::MissingAuthParameter {
                    key: "AUTH_VFR_DATA"
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn generate_verifier_rejects_non_hex_auth_vfr_data() {
        let mut session_data = BTreeMap::new();
        session_data.insert("AUTH_VFR_DATA".to_string(), "not-hex!!".to_string());
        let err = generate_verifier(b"password", &session_data, TNS_VERIFIER_TYPE_12C)
            .expect_err("non-hex AUTH_VFR_DATA must be rejected");
        assert!(
            matches!(
                err,
                ProtocolError::MissingAuthParameter {
                    key: "AUTH_VFR_DATA"
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn generate_verifier_rejects_every_verifier_but_12c() {
        let mut session_data = BTreeMap::new();
        session_data.insert("AUTH_VFR_DATA".to_string(), "aabbcc".to_string());
        for verifier_type in [
            0x9999,
            crate::thin::TNS_VERIFIER_TYPE_11G_1,
            crate::thin::TNS_VERIFIER_TYPE_11G_2,
        ] {
            let err = generate_verifier(b"password", &session_data, verifier_type)
                .expect_err("only the 12C verifier is accepted");
            assert!(
                matches!(err, ProtocolError::UnsupportedVerifier { verifier_type: v } if v == verifier_type),
                "got {err:?}"
            );
        }
    }

    #[test]
    fn verify_server_response_rejects_missing_or_malformed_responses() {
        let mut session_data = BTreeMap::new();
        assert!(matches!(
            verify_server_response(&[0u8; 32], &session_data),
            Err(ProtocolError::InvalidServerResponse)
        ));
        for bad in ["zz-not-hex", "00", &"00".repeat(17)] {
            session_data.insert("AUTH_SVR_RESPONSE".to_string(), bad.to_string());
            assert!(matches!(
                verify_server_response(&[0u8; 32], &session_data),
                Err(ProtocolError::InvalidServerResponse)
            ));
        }
    }

    #[test]
    fn verify_server_response_rejects_content_mismatch() {
        let combo_key = [0x42u8; 32];
        let plain = b"0123456789ABCDEFNOT_SERVER_RESP!";
        let ciphertext = RustCrypto
            .aes_cbc_encrypt(&combo_key, &ZERO_IV, plain)
            .unwrap();
        let mut session_data = BTreeMap::new();
        session_data.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&ciphertext));
        assert!(matches!(
            verify_server_response(&combo_key, &session_data),
            Err(ProtocolError::InvalidServerResponse)
        ));
    }

    #[test]
    fn the_wrong_length_aes_key_is_rejected() {
        assert!(matches!(
            RustCrypto.aes_cbc_decrypt(&[0u8; 10], &ZERO_IV, &[0u8; 16]),
            Err(ProtocolError::InvalidAesKey)
        ));
    }
}
