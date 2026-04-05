use aes::Aes128;
use ctr::cipher::{KeyIvInit as _, StreamCipher as _};
use ecb::cipher::block_padding::NoPadding;
use ecb::cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyInit as _};

use super::types::{CryptoKey, CryptoMethod};
use crate::firmware::FirmwareState;

type Aes128EcbEnc = ecb::Encryptor<Aes128>;
type Aes128EcbDec = ecb::Decryptor<Aes128>;
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Size of the RSA signature that is appended to the plaintext firmware
/// before encryption (RSA-2048 → 256 bytes).
pub const RSA_SIG_SIZE: usize = 256;

/// Size of the AES-128 IV appended to encrypted `DynIV` firmware images.
const IV_SIZE: usize = 16;

/// Errors that can occur during firmware encryption or decryption.
#[derive(Debug, thiserror::Error)]
pub enum CipherError {
    /// The firmware data length is not a multiple of the AES block size (16 bytes).
    #[error("firmware size is not a multiple of 16 bytes")]
    UnalignedData,
    /// The firmware is too short to contain the expected trailing metadata.
    #[error("firmware is too short to contain the expected trailing metadata")]
    DataTooShort,
    /// The crypto key is missing a required IV for CTR mode.
    #[error("crypto key is missing a required IV for CTR mode")]
    MissingIv,
    /// ECB decryption failed (e.g. padding error from the underlying crate).
    #[error("ECB decryption failed")]
    EcbDecryptFailed,
    /// Random IV generation failed.
    #[error("random IV generation failed")]
    RngFailed,
}

/// Decrypts firmware data using the provided crypto key.
///
/// The decryption method is determined by [`CryptoMethod`]:
///
/// - **ECB**: Straightforward AES-128-ECB decryption; data must be block-aligned.
/// - **CTR**: AES-128-CTR decryption using the static IV stored in the key.
/// - **CTR `DynIV`**: The file layout is `[encrypted(firmware + RSA sig)][IV (16 B)]`.
///   The RSA signature is part of the encrypted payload (it was appended to the
///   plaintext before encryption). The IV at the end is the only cleartext
///   metadata. Output: `[decrypted firmware][RSA sig]`.
///
/// # Errors
///
/// Returns [`CipherError`] on unaligned data, missing IV, data too short,
/// or ECB decryption failure.
pub fn decrypt_firmware(data: &[u8], key: &CryptoKey) -> Result<Vec<u8>, CipherError> {
    match key.identifier.method {
        CryptoMethod::AesECB128 => decrypt_ecb(data, &key.key),
        CryptoMethod::AesCTR128 => {
            let iv = key.iv.ok_or(CipherError::MissingIv)?;
            Ok(apply_ctr(data, &key.key, &iv))
        }
        CryptoMethod::AesCTR128DynIv => {
            // Need at least IV_SIZE + 1 byte of ciphertext
            if data.len() <= IV_SIZE {
                return Err(CipherError::DataTooShort);
            }

            // The IV is the last 16 bytes; everything before it is the
            // encrypted blob (firmware + RSA signature, encrypted together).
            let (ciphertext, iv_bytes) = data.split_at(data.len() - IV_SIZE);
            let iv: [u8; 16] = iv_bytes.try_into().expect("slice is exactly 16 bytes");

            // Decrypt the entire blob (firmware + RSA sig)
            Ok(apply_ctr(ciphertext, &key.key, &iv))
        }
    }
}

/// Encrypts firmware data using the provided crypto key.
///
/// The encryption method is determined by [`CryptoMethod`]:
///
/// - **ECB**: Straightforward AES-128-ECB encryption; data must be block-aligned.
/// - **CTR**: AES-128-CTR encryption using the static IV stored in the key.
/// - **CTR `DynIV`**: The input is `[plaintext firmware][RSA sig (256 B)]`. The
///   entire blob is encrypted together with a randomly generated IV, which is
///   then appended in the clear. Output: `[encrypted(firmware + RSA sig)][IV]`.
///
/// # Errors
///
/// Returns [`CipherError`] on unaligned data, missing IV, data too short,
/// or RNG failure.
pub fn encrypt_firmware(data: &[u8], key: &CryptoKey) -> Result<Vec<u8>, CipherError> {
    match key.identifier.method {
        CryptoMethod::AesECB128 => encrypt_ecb(data, &key.key),
        CryptoMethod::AesCTR128 => {
            let iv = key.iv.ok_or(CipherError::MissingIv)?;
            Ok(apply_ctr(data, &key.key, &iv))
        }
        CryptoMethod::AesCTR128DynIv => {
            if data.len() <= RSA_SIG_SIZE {
                return Err(CipherError::DataTooShort);
            }

            // Generate a random IV
            let mut iv = [0u8; 16];
            getrandom::getrandom(&mut iv).map_err(|_err| CipherError::RngFailed)?;

            // Encrypt the entire input (firmware + RSA signature together)
            let mut result = apply_ctr(data, &key.key, &iv);

            // Append the IV in the clear
            result.extend_from_slice(&iv);

            Ok(result)
        }
    }
}

/// For `DynIV` firmware, strips trailing metadata to return only the firmware
/// payload suitable for hash verification.
///
/// The RSA signature is appended to the plaintext *before* encryption, so it
/// is part of the encrypted/decrypted blob. The database hashes cover only the
/// bare firmware without the signature.
///
/// - Decrypted `DynIV` data: `[firmware][RSA sig (256 B)]` → returns `[firmware]`
/// - Encrypted `DynIV` data: `[encrypted(firmware + RSA sig)][IV (16 B)]` →
///   returns `[encrypted(firmware + RSA sig)]` (strips IV only; the RSA sig
///   cannot be separated because it is encrypted)
///
/// For non-`DynIV` methods this is a no-op and returns the full slice.
pub fn firmware_payload(data: &[u8], method: CryptoMethod, state: FirmwareState) -> &[u8] {
    match method {
        CryptoMethod::AesCTR128DynIv => {
            let trailer = match state {
                FirmwareState::Decrypted => RSA_SIG_SIZE,
                FirmwareState::Encrypted => IV_SIZE,
            };
            data.len().checked_sub(trailer).and_then(|end| data.get(..end)).unwrap_or(data)
        }
        _ => data,
    }
}

fn decrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, CipherError> {
    if !data.len().is_multiple_of(16) {
        return Err(CipherError::UnalignedData);
    }
    let dec = Aes128EcbDec::new(key.into());
    dec.decrypt_padded_vec_mut::<NoPadding>(data).map_err(|_err| CipherError::EcbDecryptFailed)
}

fn encrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, CipherError> {
    if !data.len().is_multiple_of(16) {
        return Err(CipherError::UnalignedData);
    }
    let enc = Aes128EcbEnc::new(key.into());
    Ok(enc.encrypt_padded_vec_mut::<NoPadding>(data))
}

/// AES-128-CTR is symmetric — the same operation encrypts and decrypts.
fn apply_ctr(data: &[u8], key: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    cipher.apply_keystream(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::types::{CryptoIdentifier, CryptoKey, CryptoMethod};

    fn make_key(method: CryptoMethod, with_iv: bool) -> CryptoKey {
        CryptoKey {
            identifier: CryptoIdentifier { method, key_hash: [0; 20], iv_hash: None },
            key: [0x42; 16],
            iv: if with_iv { Some([0xAB; 16]) } else { None },
        }
    }

    // ── ECB ──────────────────────────────────────────────────────

    #[test]
    fn ecb_encrypt_decrypt_round_trip() {
        let key = make_key(CryptoMethod::AesECB128, false);
        let plaintext = vec![0xDE; 256];
        let encrypted = encrypt_firmware(&plaintext, &key).expect("encrypt");
        assert_ne!(encrypted, plaintext, "ciphertext must differ from plaintext");
        let decrypted = decrypt_firmware(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ecb_rejects_unaligned_data() {
        let key = make_key(CryptoMethod::AesECB128, false);
        let data = vec![0xDE; 100]; // not a multiple of 16
        assert!(matches!(encrypt_firmware(&data, &key), Err(CipherError::UnalignedData)));
        assert!(matches!(decrypt_firmware(&data, &key), Err(CipherError::UnalignedData)));
    }

    #[test]
    fn ecb_single_block() {
        let key = make_key(CryptoMethod::AesECB128, false);
        let plaintext = vec![0x00; 16];
        let enc = encrypt_firmware(&plaintext, &key).expect("encrypt");
        assert_eq!(enc.len(), 16);
        let dec = decrypt_firmware(&enc, &key).expect("decrypt");
        assert_eq!(dec, plaintext);
    }

    // ── CTR ──────────────────────────────────────────────────────

    #[test]
    fn ctr_encrypt_decrypt_round_trip() {
        let key = make_key(CryptoMethod::AesCTR128, true);
        let plaintext = vec![0xDE; 300]; // any length, no alignment requirement
        let encrypted = encrypt_firmware(&plaintext, &key).expect("encrypt");
        assert_ne!(encrypted, plaintext);
        let decrypted = decrypt_firmware(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn ctr_rejects_missing_iv() {
        let key = make_key(CryptoMethod::AesCTR128, false);
        let data = vec![0xDE; 256];
        assert!(matches!(encrypt_firmware(&data, &key), Err(CipherError::MissingIv)));
        assert!(matches!(decrypt_firmware(&data, &key), Err(CipherError::MissingIv)));
    }

    #[test]
    fn ctr_odd_length() {
        let key = make_key(CryptoMethod::AesCTR128, true);
        let plaintext = vec![0xAA; 37]; // odd length, should work fine
        let enc = encrypt_firmware(&plaintext, &key).expect("encrypt");
        assert_eq!(enc.len(), 37);
        let dec = decrypt_firmware(&enc, &key).expect("decrypt");
        assert_eq!(dec, plaintext);
    }

    // ── DynIV ────────────────────────────────────────────────────

    #[test]
    fn dyniv_encrypt_decrypt_round_trip() {
        let key = make_key(CryptoMethod::AesCTR128DynIv, false);
        // DynIV encrypt requires data.len() > RSA_SIG_SIZE (256)
        let plaintext = vec![0xDE; 512]; // firmware(256) + RSA sig(256)
        let encrypted = encrypt_firmware(&plaintext, &key).expect("encrypt");
        // Encrypted layout: [ciphertext (512)][random IV (16)]
        assert_eq!(encrypted.len(), plaintext.len() + IV_SIZE);
        let decrypted = decrypt_firmware(&encrypted, &key).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn dyniv_random_iv_differs_between_encryptions() {
        let key = make_key(CryptoMethod::AesCTR128DynIv, false);
        let plaintext = vec![0xDE; 512];
        let enc1 = encrypt_firmware(&plaintext, &key).expect("encrypt 1");
        let enc2 = encrypt_firmware(&plaintext, &key).expect("encrypt 2");
        // The trailing IVs should differ (random), making ciphertext differ.
        // Technically there's a 2^-128 chance they match, but that won't happen.
        assert_ne!(enc1, enc2, "DynIV should produce different ciphertext each time");
        // Both must still decrypt to the same plaintext.
        assert_eq!(decrypt_firmware(&enc1, &key).expect("dec 1"), plaintext);
        assert_eq!(decrypt_firmware(&enc2, &key).expect("dec 2"), plaintext);
    }

    #[test]
    fn dyniv_rejects_short_data_encrypt() {
        let key = make_key(CryptoMethod::AesCTR128DynIv, false);
        let data = vec![0xDE; RSA_SIG_SIZE]; // exactly RSA_SIG_SIZE, must be > not >=
        assert!(matches!(encrypt_firmware(&data, &key), Err(CipherError::DataTooShort)));
    }

    #[test]
    fn dyniv_rejects_short_data_decrypt() {
        let key = make_key(CryptoMethod::AesCTR128DynIv, false);
        let data = vec![0xDE; IV_SIZE]; // exactly IV_SIZE bytes, need > IV_SIZE
        assert!(matches!(decrypt_firmware(&data, &key), Err(CipherError::DataTooShort)));
    }

    // ── firmware_payload ─────────────────────────────────────────

    #[test]
    fn payload_non_dyniv_returns_full_slice() {
        let data = vec![0xDE; 512];
        assert_eq!(firmware_payload(&data, CryptoMethod::AesECB128, FirmwareState::Decrypted).len(), 512);
        assert_eq!(firmware_payload(&data, CryptoMethod::AesCTR128, FirmwareState::Encrypted).len(), 512);
    }

    #[test]
    fn payload_dyniv_decrypted_strips_rsa_sig() {
        let data = vec![0xDE; 512];
        let payload = firmware_payload(&data, CryptoMethod::AesCTR128DynIv, FirmwareState::Decrypted);
        assert_eq!(payload.len(), 512 - RSA_SIG_SIZE);
    }

    #[test]
    fn payload_dyniv_encrypted_strips_iv() {
        let data = vec![0xDE; 512];
        let payload = firmware_payload(&data, CryptoMethod::AesCTR128DynIv, FirmwareState::Encrypted);
        assert_eq!(payload.len(), 512 - IV_SIZE);
    }

    #[test]
    fn payload_dyniv_short_data_returns_full() {
        // When data is shorter than the trailer, the function returns the full slice.
        let data = vec![0xDE; 10];
        assert_eq!(firmware_payload(&data, CryptoMethod::AesCTR128DynIv, FirmwareState::Decrypted).len(), 10);
    }
}
