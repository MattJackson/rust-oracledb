#![forbid(unsafe_code)]
//! O5LOGON (the 12c password verifier exchange) over a caller-supplied crypto [`Provider`].
//!
//! Every primitive the exchange needs goes through the provider: a DRBG, SHA-512,
//! PBKDF2-HMAC-SHA512 and unpadded AES-CBC. Each is a standard primitive with no Oracle shape; the
//! protocol (the `AUTH_PBKDF2_SPEEDY_KEY` salt suffix, the zero IV, the value padding, the
//! truncations and the hex re-encoding) stays here.
//!
//! **Custody.** Every secret intermediate (the password key and hash, both session key parts, the
//! hex temp key, the combo key, the padded plaintexts) is a [`Provider::Secret`], allocated at its
//! final length and wiped by the provider's type. The password is only borrowed. Only ciphertext hex
//! goes into `String`. An embedder whose host owns a validated module implements the trait over it
//! (its own wiping buffer as `Secret`) and builds this crate with `default-features = false`, so no
//! RustCrypto crate is linked. [`RustCryptoProvider`] (feature `o5logon-rustcrypto`, default-on) is
//! the in-crate implementation.
//!
//! Only the 12C verifier is accepted. The pre-12c combo key (MD5 over the key parts, taken when the
//! server's session key part is 48 bytes) runs only on a provider that offers [`Provider::md5`];
//! otherwise it is refused with [`ProtocolError::LegacySessionKey`] before anything else is
//! computed.

use std::collections::BTreeMap;

use hex::FromHex;

use crate::thin::TNS_VERIFIER_TYPE_12C;
use crate::{ProtocolError, Result};

/// The zero IV every O5LOGON CBC operation uses. Each encrypt starts with a fresh random block
/// (the client key part or a 16-byte salt), so the later blocks see an unpredictable IV.
const ZERO_IV: [u8; 16] = [0; 16];
/// The AES-256 key, the 12c password hash and the combo key are all this long.
const KEY_LEN: usize = 32;
/// The pre-12c (AES-192) session key part: the length that selects the MD5 combo key.
const LEGACY_SESSION_KEY_LEN: usize = 48;

/// The crypto a caller lends the O5LOGON code. The fork never names a host type; secrets live in
/// `Self::Secret`.
pub trait Provider {
    /// A wiping, fixed-length secret buffer the provider owns (store-oracle: `SecureVec`, which is
    /// `DerefMut<Target = [u8]>`).
    type Secret: core::ops::DerefMut<Target = [u8]>;
    /// A zero-filled secret of exactly `len` bytes.
    fn secret(&self, len: usize) -> core::result::Result<Self::Secret, CryptoError>;
    fn fill_random(&self, out: &mut [u8]) -> core::result::Result<(), CryptoError>;
    /// SHA-512 over the concatenation of `parts` (no caller-side concatenation buffer).
    fn sha512(&self, parts: &[&[u8]]) -> core::result::Result<Self::Secret, CryptoError>;
    /// RFC 8018 PBKDF2-HMAC-SHA512, `out_len` 1..=64.
    fn pbkdf2_hmac_sha512(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        out_len: usize,
    ) -> core::result::Result<Self::Secret, CryptoError>;
    /// Raw AES-CBC (no padding), data a non-zero multiple of 16. The ciphertext is public.
    fn aes_cbc_encrypt(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
    ) -> core::result::Result<Vec<u8>, CryptoError>;
    /// The inverse of [`Provider::aes_cbc_encrypt`]; no padding is removed.
    fn aes_cbc_decrypt(
        &self,
        key: &[u8],
        iv: &[u8; 16],
        data: &[u8],
    ) -> core::result::Result<Self::Secret, CryptoError>;
    /// Constant-time equality.
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool;
    /// Legacy digest for the 11G verifier; `None` = not offered (the verifier is refused).
    fn sha1(&self, _parts: &[&[u8]]) -> Option<core::result::Result<[u8; 20], CryptoError>> {
        None
    }
    /// Legacy digest for the 48-byte combo key; `None` = not offered (the branch is refused).
    fn md5(&self, _data: &[u8]) -> Option<core::result::Result<[u8; 16], CryptoError>> {
        None
    }
}

/// A provider error. The class survives the boundary: a refusal verdict (the module does not offer
/// these parameters) vs a module failure. The reason is static text with no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CryptoError {
    Unavailable(&'static str),
    Failed(&'static str),
}

/// A provider answer as this crate's error.
fn lift<P: Provider, T>(_p: &P, r: core::result::Result<T, CryptoError>) -> Result<T> {
    r.map_err(|e| match e {
        CryptoError::Unavailable(reason) => ProtocolError::CryptoUnavailable(reason),
        CryptoError::Failed(reason) => ProtocolError::CryptoFailed(reason),
    })
}

/// The phase-two verifier material. `combo_key` stays in the provider's secret custody.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedPassword<S> {
    pub session_key: String,
    pub speedy_key: Option<String>,
    pub password: String,
    pub combo_key: S,
}

/// The phase-two verifier material for `password` against the server's phase-one
/// `session_data`, computed over `p`. Only [`TNS_VERIFIER_TYPE_12C`] is accepted: the 10G/11G
/// verifiers need SHA-1 and AES-192 session keys, which this code does not offer.
pub fn generate_verifier_with<P: Provider>(
    p: &P,
    password: &[u8],
    session_data: &BTreeMap<String, String>,
    verifier_type: u32,
) -> Result<EncryptedPassword<P::Secret>> {
    if verifier_type != TNS_VERIFIER_TYPE_12C {
        return Err(ProtocolError::UnsupportedVerifier { verifier_type });
    }
    let verifier_data = decode_session_hex(session_data, "AUTH_VFR_DATA")?;
    let iterations = parse_session_u32(session_data, "AUTH_PBKDF2_VGEN_COUNT")?;
    let mut salt = verifier_data.clone();
    salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
    let password_key = lift(p, p.pbkdf2_hmac_sha512(password, &salt, iterations, 64))?;
    let digest = lift(p, p.sha512(&[password_key.as_ref(), &verifier_data]))?;
    let password_hash = digest
        .as_ref()
        .get(..KEY_LEN)
        .ok_or(ProtocolError::CryptoFailed("SHA-512 answered short"))?;

    let encoded_server_key = decode_session_hex(session_data, "AUTH_SESSKEY")?;
    if encoded_server_key.is_empty() || !encoded_server_key.len().is_multiple_of(16) {
        return Err(ProtocolError::TtcDecode(
            "AES-CBC ciphertext length is not block aligned",
        ));
    }
    let part_a = lift(
        p,
        p.aes_cbc_decrypt(password_hash, &ZERO_IV, &encoded_server_key),
    )?;
    let part_a = part_a.as_ref();
    if part_a.len() < KEY_LEN {
        return Err(ProtocolError::TtcDecode("session key too short"));
    }
    let legacy = part_a.len() == LEGACY_SESSION_KEY_LEN;
    if legacy && p.md5(&[]).is_none() {
        return Err(ProtocolError::LegacySessionKey);
    }
    let mut part_b = lift(p, p.secret(part_a.len()))?;
    lift(p, p.fill_random(part_b.as_mut()))?;
    // CBC is prefix-preserving: the unpadded encryption of the aligned part B is exactly the
    // prefix the protocol keeps of its padded encryption.
    let encoded_client_key = lift(
        p,
        p.aes_cbc_encrypt(password_hash, &ZERO_IV, part_b.as_ref()),
    )?;

    let (session_key, combo_key) = if legacy {
        let session_key = hex_upper_truncated(&encoded_client_key, 96);
        let mut mixed = lift(p, p.secret(24))?;
        for (ix, out) in mixed.as_mut().iter_mut().enumerate() {
            *out = part_a[16 + ix] ^ part_b.as_ref()[16 + ix];
        }
        let first = md5(p, &mixed.as_ref()[..16])?;
        let second = md5(p, &mixed.as_ref()[16..])?;
        let mut combo = lift(p, p.secret(KEY_LEN))?;
        combo.as_mut()[..16].copy_from_slice(&first);
        combo.as_mut()[16..].copy_from_slice(&second);
        (session_key, combo)
    } else {
        let session_key = hex_upper_truncated(&encoded_client_key, 2 * KEY_LEN);
        let csk_salt = decode_session_hex(session_data, "AUTH_PBKDF2_CSK_SALT")?;
        let sder_iterations = parse_session_u32(session_data, "AUTH_PBKDF2_SDER_COUNT")?;
        // hex_upper(part_b[..32] || part_a[..32]), written straight into a secret.
        let mut temp_key_hex = lift(p, p.secret(4 * KEY_LEN))?;
        let halves = part_b.as_ref()[..KEY_LEN].iter().chain(&part_a[..KEY_LEN]);
        for (pair, byte) in temp_key_hex.as_mut().chunks_mut(2).zip(halves) {
            pair[0] = HEX_UPPER[usize::from(byte >> 4)];
            pair[1] = HEX_UPPER[usize::from(byte & 0x0f)];
        }
        let combo = lift(
            p,
            p.pbkdf2_hmac_sha512(temp_key_hex.as_ref(), &csk_salt, sder_iterations, KEY_LEN),
        )?;
        (session_key, combo)
    };

    // The speedy key: a random salt then the 64-byte password key, 80 aligned bytes whose
    // unpadded encryption is the 160 hex characters the protocol keeps.
    let mut speedy_plain = lift(p, p.secret(16 + 64))?;
    lift(p, p.fill_random(&mut speedy_plain.as_mut()[..16]))?;
    speedy_plain.as_mut()[16..].copy_from_slice(password_key.as_ref());
    let speedy = lift(
        p,
        p.aes_cbc_encrypt(combo_key.as_ref(), &ZERO_IV, speedy_plain.as_ref()),
    )?;

    let mut salt = [0u8; 16];
    lift(p, p.fill_random(&mut salt))?;
    let encrypted_password = encrypt_with_salt(p, combo_key.as_ref(), &salt, password)?;
    Ok(EncryptedPassword {
        session_key,
        speedy_key: Some(hex_upper(&speedy)),
        password: hex_upper(&encrypted_password),
        combo_key,
    })
}

fn md5<P: Provider>(p: &P, data: &[u8]) -> Result<[u8; 16]> {
    match p.md5(data) {
        Some(r) => lift(p, r),
        None => Err(ProtocolError::LegacySessionKey),
    }
}

/// Encrypt the old/new password pair with the session combo key for the change-password call
/// (reference messages/auth.pyx `_encrypt_passwords`: one shared random salt, AES-CBC under
/// `_combo_key`, upper-hex encoding).
pub fn encrypt_change_password_pair_with<P: Provider>(
    p: &P,
    combo_key: &[u8],
    old_password: &[u8],
    new_password: &[u8],
) -> Result<(String, String)> {
    let mut salt = [0u8; 16];
    lift(p, p.fill_random(&mut salt))?;
    let encrypted_old = encrypt_with_salt(p, combo_key, &salt, old_password)?;
    let encrypted_new = encrypt_with_salt(p, combo_key, &salt, new_password)?;
    Ok((hex_upper(&encrypted_old), hex_upper(&encrypted_new)))
}

/// Check the server's proof: `AUTH_SVR_RESPONSE` decrypts under the combo key to a block whose
/// bytes 16..32 are `SERVER_TO_CLIENT` (compared with the provider's constant-time equality).
pub fn verify_server_response_with<P: Provider>(
    p: &P,
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
    let response = lift(p, p.aes_cbc_decrypt(combo_key, &ZERO_IV, &encoded_response))?;
    match response.as_ref().get(16..32) {
        Some(marker) if p.ct_eq(marker, b"SERVER_TO_CLIENT") => Ok(()),
        _ => Err(ProtocolError::InvalidServerResponse),
    }
}

/// `salt || text`, value-padded (a whole block when aligned) in a secret, encrypted unpadded.
fn encrypt_with_salt<P: Provider>(
    p: &P,
    key: &[u8],
    salt: &[u8; 16],
    text: &[u8],
) -> Result<Vec<u8>> {
    let len = 16 + text.len();
    let pad = 16 - len % 16;
    let mut plain = lift(p, p.secret(len + pad))?;
    let buf = plain.as_mut();
    buf[..16].copy_from_slice(salt);
    buf[16..len].copy_from_slice(text);
    buf[len..].fill(pad as u8);
    lift(p, p.aes_cbc_encrypt(key, &ZERO_IV, plain.as_ref()))
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

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
    encrypt_change_password_pair, generate_verifier, verify_server_response, RustCryptoProvider,
    SecretBytes,
};

#[cfg(feature = "o5logon-rustcrypto")]
mod rustcrypto {
    use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
    use aes::Aes256;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::{Digest, Sha512};
    use zeroize::Zeroize;

    use std::collections::BTreeMap;

    use super::{CryptoError, EncryptedPassword, Provider};
    use crate::Result;

    /// [`Provider`] over the RustCrypto crates (`pbkdf2`, `sha2`, `aes`) and the OS RNG. It offers
    /// neither SHA-1 nor MD5, so the 11G verifier and the 48-byte combo key are refused.
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RustCryptoProvider;

    /// A secret buffer wiped on drop.
    #[derive(Clone, Default, PartialEq, Eq)]
    pub struct SecretBytes(Vec<u8>);

    impl From<Vec<u8>> for SecretBytes {
        fn from(bytes: Vec<u8>) -> Self {
            Self(bytes)
        }
    }

    impl Drop for SecretBytes {
        fn drop(&mut self) {
            self.0.zeroize();
        }
    }

    impl core::fmt::Debug for SecretBytes {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("SecretBytes(..)")
        }
    }

    impl core::ops::Deref for SecretBytes {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            &self.0
        }
    }

    impl core::ops::DerefMut for SecretBytes {
        fn deref_mut(&mut self) -> &mut [u8] {
            &mut self.0
        }
    }

    // RustCrypto never refuses as a policy: every error is `CryptoError::Failed`.

    fn aligned(data: &[u8]) -> core::result::Result<(), CryptoError> {
        if data.is_empty() || !data.len().is_multiple_of(16) {
            return Err(CryptoError::Failed(
                "AES-CBC data is not a non-empty multiple of 16 bytes",
            ));
        }
        Ok(())
    }

    fn cipher(key: &[u8]) -> core::result::Result<Aes256, CryptoError> {
        Aes256::new_from_slice(key).map_err(|_| CryptoError::Failed("invalid AES key length"))
    }

    impl Provider for RustCryptoProvider {
        type Secret = SecretBytes;

        fn secret(&self, len: usize) -> core::result::Result<SecretBytes, CryptoError> {
            Ok(SecretBytes(vec![0; len]))
        }

        fn fill_random(&self, out: &mut [u8]) -> core::result::Result<(), CryptoError> {
            OsRng
                .try_fill_bytes(out)
                .map_err(|_| CryptoError::Failed("the OS random source failed"))
        }

        fn sha512(&self, parts: &[&[u8]]) -> core::result::Result<SecretBytes, CryptoError> {
            let mut hasher = Sha512::new();
            for part in parts {
                hasher.update(part);
            }
            let mut digest = hasher.finalize();
            let out = SecretBytes(digest.to_vec());
            digest.as_mut_slice().zeroize();
            Ok(out)
        }

        fn pbkdf2_hmac_sha512(
            &self,
            password: &[u8],
            salt: &[u8],
            iterations: u32,
            out_len: usize,
        ) -> core::result::Result<SecretBytes, CryptoError> {
            if iterations == 0 || out_len == 0 || out_len > 64 {
                return Err(CryptoError::Failed(
                    "PBKDF2-HMAC-SHA512 parameters out of range",
                ));
            }
            let mut out = SecretBytes(vec![0; out_len]);
            pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut out.0);
            Ok(out)
        }

        fn aes_cbc_encrypt(
            &self,
            key: &[u8],
            iv: &[u8; 16],
            data: &[u8],
        ) -> core::result::Result<Vec<u8>, CryptoError> {
            aligned(data)?;
            let cipher = cipher(key)?;
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

        fn aes_cbc_decrypt(
            &self,
            key: &[u8],
            iv: &[u8; 16],
            data: &[u8],
        ) -> core::result::Result<SecretBytes, CryptoError> {
            aligned(data)?;
            let cipher = cipher(key)?;
            let mut out = SecretBytes(data.to_vec());
            let mut previous = *iv;
            for block in out.0.chunks_mut(16) {
                let mut current = [0u8; 16];
                current.copy_from_slice(block);
                let block_ref = aes::cipher::generic_array::GenericArray::from_mut_slice(block);
                cipher.decrypt_block(block_ref);
                for (byte, prev) in block.iter_mut().zip(previous) {
                    *byte ^= prev;
                }
                previous = current;
            }
            Ok(out)
        }

        fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
            a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
        }
    }

    /// [`super::generate_verifier_with`] over [`RustCryptoProvider`] (the upstream name).
    pub fn generate_verifier(
        password: &[u8],
        session_data: &BTreeMap<String, String>,
        verifier_type: u32,
    ) -> Result<EncryptedPassword<SecretBytes>> {
        super::generate_verifier_with(&RustCryptoProvider, password, session_data, verifier_type)
    }

    /// [`super::verify_server_response_with`] over [`RustCryptoProvider`] (the upstream name).
    pub fn verify_server_response(
        combo_key: &[u8],
        session_data: &BTreeMap<String, String>,
    ) -> Result<()> {
        super::verify_server_response_with(&RustCryptoProvider, combo_key, session_data)
    }

    /// [`super::encrypt_change_password_pair_with`] over [`RustCryptoProvider`] (the upstream name).
    pub fn encrypt_change_password_pair(
        combo_key: &[u8],
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<(String, String)> {
        super::encrypt_change_password_pair_with(
            &RustCryptoProvider,
            combo_key,
            old_password,
            new_password,
        )
    }
}

#[cfg(all(test, feature = "o5logon-rustcrypto"))]
mod tests {
    use super::*;
    use std::cell::Cell;

    // Every error variant this file can raise is server-response-driven: a hostile or buggy
    // listener controls `session_data`, so a missing or malformed AUTH_* key must fail closed
    // with the right typed error, never panic.

    const P: RustCryptoProvider = RustCryptoProvider;

    fn unhex(text: &str) -> Vec<u8> {
        Vec::from_hex(text.replace(' ', "")).unwrap()
    }

    /// RustCrypto that counts its random draws, and may offer MD5 (as a refusing stub).
    #[derive(Default)]
    struct Counting {
        random: Cell<usize>,
        offers_md5: bool,
    }

    impl Provider for Counting {
        type Secret = SecretBytes;
        fn secret(&self, len: usize) -> core::result::Result<SecretBytes, CryptoError> {
            P.secret(len)
        }
        fn fill_random(&self, out: &mut [u8]) -> core::result::Result<(), CryptoError> {
            self.random.set(self.random.get() + 1);
            P.fill_random(out)
        }
        fn sha512(&self, parts: &[&[u8]]) -> core::result::Result<SecretBytes, CryptoError> {
            P.sha512(parts)
        }
        fn pbkdf2_hmac_sha512(
            &self,
            password: &[u8],
            salt: &[u8],
            iterations: u32,
            out_len: usize,
        ) -> core::result::Result<SecretBytes, CryptoError> {
            P.pbkdf2_hmac_sha512(password, salt, iterations, out_len)
        }
        fn aes_cbc_encrypt(
            &self,
            key: &[u8],
            iv: &[u8; 16],
            data: &[u8],
        ) -> core::result::Result<Vec<u8>, CryptoError> {
            P.aes_cbc_encrypt(key, iv, data)
        }
        fn aes_cbc_decrypt(
            &self,
            key: &[u8],
            iv: &[u8; 16],
            data: &[u8],
        ) -> core::result::Result<SecretBytes, CryptoError> {
            P.aes_cbc_decrypt(key, iv, data)
        }
        fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
            P.ct_eq(a, b)
        }
        fn md5(&self, _: &[u8]) -> Option<core::result::Result<[u8; 16], CryptoError>> {
            self.offers_md5
                .then_some(Err(CryptoError::Failed("MD5 stub")))
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
        assert_eq!(P.aes_cbc_encrypt(&key, &iv, &plain).unwrap(), cipher);
        assert_eq!(
            P.aes_cbc_decrypt(&key, &iv, &cipher).unwrap().as_ref(),
            plain
        );
        // No padding is added or stripped: the last block alone decrypts under IV = C3.
        let c3: [u8; 16] = cipher[32..48].try_into().unwrap();
        assert_eq!(
            P.aes_cbc_decrypt(&key, &c3, &cipher[48..])
                .unwrap()
                .as_ref(),
            &plain[48..]
        );
        for bad in [&plain[..15], &[][..]] {
            assert!(P.aes_cbc_encrypt(&key, &iv, bad).is_err());
            assert!(P.aes_cbc_decrypt(&key, &iv, bad).is_err());
        }
        assert!(P.aes_cbc_encrypt(&key[..24], &iv, &plain).is_err());
    }

    #[test]
    fn rustcrypto_pbkdf2_sha512_matches_the_known_answers() {
        let k4 = P
            .pbkdf2_hmac_sha512(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                64,
            )
            .unwrap();
        assert_eq!(
            k4.as_ref(),
            unhex(
                "8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71\
                 115b59f9e60cd9532fa33e0f75aefe30225c583a186cd82bd4daea9724a3d3b8"
            )
        );
        let salt: Vec<u8> = (0u8..16).collect();
        let k5 = unhex(
            "03a026148b62ec22a561da0f895f637f577d965a77ee8dbb5a6b3c671f1fc0c2\
             4608e8a027302d84e5b73e0f971793e7362627b10b08cf537936dca7ac49bbf3",
        );
        let out = P
            .pbkdf2_hmac_sha512(b"correct horse battery staple", &salt, 1000, 64)
            .unwrap();
        assert_eq!(out.as_ref(), k5);
        let short = P
            .pbkdf2_hmac_sha512(b"correct horse battery staple", &salt, 1000, 32)
            .unwrap();
        assert_eq!(short.as_ref(), &k5[..32], "a shorter key is the prefix");
        for (iterations, len) in [(0, 64), (1, 0), (1, 65)] {
            assert!(P.pbkdf2_hmac_sha512(b"p", b"s", iterations, len).is_err());
        }
    }

    /// The server's half of O5LOGON, written from the protocol: a 12c login of `password`.
    struct Server {
        session_data: BTreeMap<String, String>,
        password_hash: Vec<u8>,
        password_key: Vec<u8>,
        part_a: Vec<u8>,
    }

    impl Server {
        fn new(password: &[u8], part_a_len: usize) -> Self {
            let vfr = unhex("8a5e3f0c1b2d4e6f7081920a1b2c3d4e");
            let mut salt = vfr.clone();
            salt.extend_from_slice(b"AUTH_PBKDF2_SPEEDY_KEY");
            let password_key = P
                .pbkdf2_hmac_sha512(password, &salt, 4096, 64)
                .unwrap()
                .as_ref()
                .to_vec();
            let password_hash = P.sha512(&[&password_key, &vfr]).unwrap().as_ref()[..32].to_vec();
            let part_a: Vec<u8> = (0..part_a_len).map(|i| (i * 7 + 3) as u8).collect();
            let sesskey = P
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

        fn combo_key(&self, session_key: &str) -> Vec<u8> {
            let encoded = Vec::from_hex(session_key).unwrap();
            let part_b = P
                .aes_cbc_decrypt(&self.password_hash, &ZERO_IV, &encoded)
                .unwrap();
            let mut temp = part_b.as_ref()[..32].to_vec();
            temp.extend_from_slice(&self.part_a[..32]);
            P.pbkdf2_hmac_sha512(hex_upper(&temp).as_bytes(), &[0x5a; 16], 3, 32)
                .unwrap()
                .as_ref()
                .to_vec()
        }
    }

    #[test]
    fn a_12c_login_round_trips_with_the_server() {
        let password = b"a-correct-password";
        let server = Server::new(password, 32);
        let encrypted =
            generate_verifier_with(&P, password, &server.session_data, TNS_VERIFIER_TYPE_12C)
                .unwrap();
        assert_eq!(encrypted.session_key.len(), 64);
        let combo = server.combo_key(&encrypted.session_key);
        assert_eq!(
            encrypted.combo_key.as_ref(),
            combo,
            "both sides derive one combo key"
        );
        // AUTH_PASSWORD: salt, then the password, value-padded.
        let sealed = Vec::from_hex(&encrypted.password).unwrap();
        let plain = P.aes_cbc_decrypt(&combo, &ZERO_IV, &sealed).unwrap();
        let plain = plain.as_ref();
        let pad = usize::from(*plain.last().unwrap());
        assert_eq!(&plain[16..plain.len() - pad], password);
        // AUTH_PBKDF2_SPEEDY_KEY: salt, then the 64-byte password key, 160 hex characters.
        let speedy = Vec::from_hex(encrypted.speedy_key.as_deref().unwrap()).unwrap();
        assert_eq!(speedy.len(), 80);
        let plain = P.aes_cbc_decrypt(&combo, &ZERO_IV, &speedy).unwrap();
        assert_eq!(&plain.as_ref()[16..], &server.password_key[..]);
        // The server's proof verifies; one made under another key does not.
        let mut proof = vec![0x11u8; 16];
        proof.extend_from_slice(b"SERVER_TO_CLIENT");
        let mut answer = BTreeMap::new();
        let sealed = P.aes_cbc_encrypt(&combo, &ZERO_IV, &proof).unwrap();
        answer.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&sealed));
        verify_server_response_with(&P, &combo, &answer).unwrap();
        let forged = P.aes_cbc_encrypt(&[9u8; 32], &ZERO_IV, &proof).unwrap();
        answer.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&forged));
        assert!(matches!(
            verify_server_response_with(&P, &combo, &answer),
            Err(ProtocolError::InvalidServerResponse)
        ));
        let (old, new) = encrypt_change_password_pair_with(&P, &combo, b"old", b"new").unwrap();
        assert_eq!((old.len(), new.len()), (64, 64));
    }

    #[test]
    fn the_md5_session_key_is_refused_before_any_key_is_drawn() {
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
        // A provider that offers MD5 reaches it, and its answer is the caller's.
        let offering = Counting {
            offers_md5: true,
            ..Counting::default()
        };
        let err = generate_verifier_with(
            &offering,
            b"pw",
            &server.session_data,
            TNS_VERIFIER_TYPE_12C,
        )
        .unwrap_err();
        assert!(
            matches!(err, ProtocolError::CryptoFailed("MD5 stub")),
            "got {err:?}"
        );
    }

    #[test]
    fn generate_verifier_rejects_missing_or_malformed_auth_vfr_data() {
        let mut session_data = BTreeMap::new();
        for value in [None, Some("not-hex!!")] {
            if let Some(v) = value {
                session_data.insert("AUTH_VFR_DATA".to_string(), v.to_string());
            }
            let err = generate_verifier_with(&P, b"password", &session_data, TNS_VERIFIER_TYPE_12C)
                .expect_err("a bad AUTH_VFR_DATA must be rejected");
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
            let err = generate_verifier_with(&P, b"password", &session_data, verifier_type)
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
            verify_server_response_with(&P, &[0u8; 32], &session_data),
            Err(ProtocolError::InvalidServerResponse)
        ));
        for bad in ["zz-not-hex".to_string(), "00".to_string(), "00".repeat(17)] {
            session_data.insert("AUTH_SVR_RESPONSE".to_string(), bad);
            assert!(matches!(
                verify_server_response_with(&P, &[0u8; 32], &session_data),
                Err(ProtocolError::InvalidServerResponse)
            ));
        }
        let combo_key = [0x42u8; 32];
        let ciphertext = P
            .aes_cbc_encrypt(&combo_key, &ZERO_IV, b"0123456789ABCDEFNOT_SERVER_RESP!")
            .unwrap();
        session_data.insert("AUTH_SVR_RESPONSE".to_string(), hex_upper(&ciphertext));
        assert!(matches!(
            verify_server_response_with(&P, &combo_key, &session_data),
            Err(ProtocolError::InvalidServerResponse)
        ));
    }

    #[test]
    fn a_secret_is_wiped_when_dropped_and_never_printed() {
        let s = P.pbkdf2_hmac_sha512(b"pw", b"salt", 1, 32).unwrap();
        assert_eq!(format!("{s:?}"), "SecretBytes(..)");
    }
}
