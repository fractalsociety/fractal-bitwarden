# Bitwarden native crypto port

Upstream: https://github.com/bitwarden/sdk-internal
Fork: https://github.com/fractalsociety/fractal-bitwarden
Pinned commit: `7d5b1010297d6f2352b55c3d2ff27352e37433cd`.

`src/cbc.rs` derives from
`crates/bitwarden-crypto/src/hazmat/symmetric_encryption/aes256_cbc_hmac_sha256_ae.rs`.
Copyright Bitwarden Inc. The GPL-3.0-only option is selected; full license is
included. No source from `bitwarden_license` is included.

Changes: `no_std` + `alloc`; stable RustCrypto 0.8/0.1 APIs; zeroizing decrypt
buffer including error paths; bounded, strict type-2 EncString wrapper. Upstream
test vector is retained in the permission-manager integration tests. This is a
small native port of actual upstream code, not the entire SDK or server.

Only authenticated type 2 is supported. Type 0, asymmetric, and COSE/type 7
formats are rejected explicitly. Existing decrypted 64-byte item keys must be
provided by a trusted owner unlock/import path. Account login, password KDF,
organization key unwrap, vault sync, and browser extensions are not implemented.
Fresh IVs must come from the kernel CSPRNG; no host RNG fallback exists.
