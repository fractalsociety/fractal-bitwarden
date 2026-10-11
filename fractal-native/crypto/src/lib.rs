//! Bounded native port of Bitwarden's authenticated type-2 EncString primitive.
#![no_std]
extern crate alloc;
use alloc::{format, string::String, vec::Vec};
use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::Zeroizing;
mod cbc;

pub const MAX_SECRET: usize = 8192;
const MAX_ENCODED: usize = 11200;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    FormatWrong,
    IntegrityCheckFailed,
    Bounds,
    Entropy,
}
/// Host/kernel adapter must fill from an initialized cryptographic RNG or fail.
pub trait Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error>;
}
pub struct Key(Zeroizing<[u8; 64]>);
impl Key {
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}
pub struct EncString {
    iv: [u8; 16],
    mac: [u8; 32],
    data: Vec<u8>,
}
impl EncString {
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > MAX_ENCODED {
            return Err(Error::Bounds);
        }
        let mut parts = text
            .strip_prefix("2.")
            .ok_or(Error::FormatWrong)?
            .split('|');
        let iv = STANDARD
            .decode(parts.next().ok_or(Error::FormatWrong)?)
            .map_err(|_| Error::FormatWrong)?;
        let data = STANDARD
            .decode(parts.next().ok_or(Error::FormatWrong)?)
            .map_err(|_| Error::FormatWrong)?;
        let mac = STANDARD
            .decode(parts.next().ok_or(Error::FormatWrong)?)
            .map_err(|_| Error::FormatWrong)?;
        if parts.next().is_some()
            || data.is_empty()
            || data.len() % 16 != 0
            || data.len() > MAX_SECRET + 16
        {
            return Err(Error::FormatWrong);
        }
        Ok(Self {
            iv: iv.try_into().map_err(|_| Error::FormatWrong)?,
            mac: mac.try_into().map_err(|_| Error::FormatWrong)?,
            data,
        })
    }
    pub fn encode(&self) -> String {
        format!(
            "2.{}|{}|{}",
            STANDARD.encode(self.iv),
            STANDARD.encode(&self.data),
            STANDARD.encode(self.mac)
        )
    }
    pub fn seal(key: &Key, plaintext: &[u8], rng: &mut impl Entropy) -> Result<Self, Error> {
        if plaintext.len() > MAX_SECRET {
            return Err(Error::Bounds);
        }
        let mut iv = [0; 16];
        rng.fill(&mut iv)?;
        let (mac, data) = cbc::Aes256CbcHmacSha256::encrypt(&iv, plaintext, &key.0);
        Ok(Self { iv, mac, data })
    }
    pub fn open(&self, key: &Key) -> Result<Zeroizing<Vec<u8>>, Error> {
        cbc::Aes256CbcHmacSha256::decrypt(&self.iv, &self.data, &self.mac, &key.0)
    }
}
