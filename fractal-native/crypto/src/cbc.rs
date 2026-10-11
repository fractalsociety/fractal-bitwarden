// SPDX-License-Identifier: GPL-3.0-only
// Derived from Bitwarden Inc. sdk-internal; see UPSTREAM.md for provenance and changes.
//! # Legacy AES-256-CBC-HMAC-SHA256 operations
//!
//! Aes256CbcHmacSha256 is the construct used in type 2 EncStrings. It is authenticated encryption
//! (AE) via Encrypt-then-MAC, but has no support for associated data (it is not AEAD).

use alloc::vec::Vec;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::Mac;
use subtle::ConstantTimeEq;

use crate::Error as SymmetricEncryptionError;
use zeroize::Zeroizing;

type HmacSha256 = hmac::Hmac<sha2::Sha256>;

pub(crate) const IV_SIZE: usize = 16;
pub(crate) const ENC_KEY_SIZE: usize = 32;
pub(crate) const MAC_KEY_SIZE: usize = 32;
pub(crate) const KEY_SIZE: usize = ENC_KEY_SIZE + MAC_KEY_SIZE;
pub(crate) const MAC_SIZE: usize = 32;

/// The legacy AES-256-CBC-HMAC-SHA256 Encrypt-then-MAC cipher. The 64-byte composite key is the
/// AES-256-CBC encryption sub-key (first 32 bytes) followed by the HMAC-SHA256 authentication
/// sub-key (last 32 bytes).
pub(crate) struct Aes256CbcHmacSha256;

impl Aes256CbcHmacSha256 {
    /// Encrypt using AES-256 in CBC mode, returning the MAC over the IV and ciphertext along
    /// with the ciphertext.
    ///
    /// A fresh, cryptographically random IV must be supplied for every message encrypted under a
    /// given key; generating it is the caller's responsibility.
    pub(crate) fn encrypt(
        iv: &[u8; IV_SIZE],
        plaintext: &[u8],
        key: &[u8; KEY_SIZE],
    ) -> ([u8; MAC_SIZE], Vec<u8>) {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let data = cbc::Encryptor::<aes::Aes256>::new(enc_key.into(), iv.into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mac = calculate_mac(iv, &data, mac_key);

        (mac, data)
    }

    /// Decrypt using AES-256 in CBC mode, validating the MAC over the IV and ciphertext.
    pub(crate) fn decrypt(
        iv: &[u8; IV_SIZE],
        ciphertext: &[u8],
        mac: &[u8; MAC_SIZE],
        key: &[u8; KEY_SIZE],
    ) -> Result<Zeroizing<Vec<u8>>, SymmetricEncryptionError> {
        let (enc_key, mac_key) = split_to_subkeys(key);

        let expected_mac = calculate_mac(iv, ciphertext, mac_key);
        if expected_mac.ct_ne(mac).into() {
            return Err(SymmetricEncryptionError::IntegrityCheckFailed);
        }

        // Decrypt data in place in a copy of the ciphertext
        let mut data = Zeroizing::new(ciphertext.to_vec());
        let decrypted_slice = cbc::Decryptor::<aes::Aes256>::new(enc_key.into(), iv.into())
            .decrypt_padded_mut::<Pkcs7>(&mut data)
            .map_err(|_| SymmetricEncryptionError::FormatWrong)?;

        // Decryption returns a subslice of the buffer; truncate to the subslice length instead of
        // cloning it
        let decrypted_len = decrypted_slice.len();
        data.truncate(decrypted_len);

        Ok(data)
    }
}

/// Splits the 64-byte composite key into zero-copy views over its encryption and MAC halves.
fn split_to_subkeys(key: &[u8; KEY_SIZE]) -> (&[u8; ENC_KEY_SIZE], &[u8; MAC_KEY_SIZE]) {
    let (enc_key, mac_key) = key.split_at(ENC_KEY_SIZE);
    let enc_key = enc_key
        .try_into()
        .expect("first half of a 64-byte key is always 32 bytes");
    let mac_key = mac_key
        .try_into()
        .expect("second half of a 64-byte key is always 32 bytes");
    (enc_key, mac_key)
}

/// Generate a MAC using HMAC-SHA256 over the IV and ciphertext, without length prefixes or
/// associated data.
fn calculate_mac(iv: &[u8], data: &[u8], mac_key: &[u8; MAC_KEY_SIZE]) -> [u8; MAC_SIZE] {
    let mut hmac =
        HmacSha256::new_from_slice(mac_key).expect("hmac new_from_slice should not fail");
    hmac.update(iv);
    hmac.update(data);
    let mac: [u8; MAC_SIZE] = (*hmac.finalize().into_bytes())
        .try_into()
        // This is safe because HMAC-SHA256 output size is always 32 bytes
        .expect("HMAC output size to be correct");
    mac
}

