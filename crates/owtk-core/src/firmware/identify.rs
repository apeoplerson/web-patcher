use super::registry::known_firmwares;
use super::types::{FirmwareDescriptor, FirmwareState, IdentifiedFirmware};
use crate::crypto::cipher::{RSA_SIG_SIZE, decrypt_firmware};
use crate::crypto::{CryptoKey, CryptoMethod, partial_hash, sha1_hash};

/// Attempts to identify a firmware image by hashing it and matching
/// against the known firmware database loaded from `src/firmware/defs/`.
///
/// When `keys` is provided, the function can also identify encrypted
/// firmware that is not in the database by trial-decrypting with each
/// available key and matching the decrypted result.  This is especially
/// useful for `DynIV` firmware where each re-encryption produces a
/// different random IV, making the encrypted hash unique every time.
///
/// Returns the first match found, or `None` if the firmware is
/// unrecognised. The matching strategy is layered:
///
/// 1. **Exact match** — full-file SHA-1 against `encrypted_hash` /
///    `decrypted_hash`.  This is the highest-confidence path and also
///    logs the partial hash to the console for database population.
/// 2. **Partial match** — SHA-1 of the first [`PARTIAL_HASH_SIZE`] bytes
///    against `decrypted_partial_hash`.  This identifies firmware that
///    has been modified (e.g. patched) while leaving the vector table
///    intact.  The result has `exact_match = false` so the UI can
///    indicate the image is recognised but not stock.
/// 3. **Trial decryption** (requires `keys`) — for each unique crypto
///    identifier in the database that has a matching user key, decrypt
///    the firmware and match the result against `decrypted_hash` /
///    `decrypted_partial_hash`.  This catches encrypted firmware whose
///    specific encrypted hash is not in the database.
///
/// For `DynIV` firmware, the decrypted hash in the database covers only the
/// firmware payload (without the trailing 256-byte RSA signature), so this
/// function also tries stripping the signature before matching.
pub fn identify_firmware(data: &[u8], keys: Option<&[CryptoKey]>) -> Option<IdentifiedFirmware> {
    if data.is_empty() {
        return None;
    }

    let firmwares = known_firmwares();

    let hash = sha1_hash(data);

    // Also compute a hash with the last 256 bytes (RSA signature) stripped,
    // for matching decrypted `DynIV` firmware loaded from disk.
    let hash_stripped = data.len().checked_sub(RSA_SIG_SIZE).and_then(|end| data.get(..end)).map(sha1_hash);

    // ── Pass 1: exact full-file hash match ──────────────────────────
    for descriptor in firmwares {
        let ec = descriptor.crypto_identifier;

        if let Some(encrypted_hash) = &descriptor.encrypted_hash
            && *encrypted_hash == hash
        {
            return Some(IdentifiedFirmware {
                descriptor,
                state: FirmwareState::Encrypted,
                exact_match: true,
                effective_crypto: ec,
            });
        }

        if let Some(decrypted_hash) = &descriptor.decrypted_hash {
            // For non-`DynIV` firmware, match the full-file hash directly.
            if *decrypted_hash == hash {
                return Some(IdentifiedFirmware {
                    descriptor,
                    state: FirmwareState::Decrypted,
                    exact_match: true,
                    effective_crypto: ec,
                });
            }

            // For `DynIV` firmware, also try matching with the RSA signature stripped.
            if descriptor.crypto_identifier.method == CryptoMethod::AesCTR128DynIv
                && let Some(stripped) = &hash_stripped
                && *decrypted_hash == *stripped
            {
                return Some(IdentifiedFirmware {
                    descriptor,
                    state: FirmwareState::Decrypted,
                    exact_match: true,
                    effective_crypto: ec,
                });
            }
        }
    }

    // ── Pass 2: partial hash fallback (decrypted only) ──────────────
    //
    // The partial hash covers the Cortex-M vector table — the first
    // PARTIAL_HASH_SIZE bytes — which is never modified by patches.
    // We only attempt this for decrypted identification because patches
    // are applied to the decrypted image.
    if let Some(p_hash) = partial_hash(data) {
        // For `DynIV` firmware the payload (without trailing RSA sig) is
        // what we store the partial hash against, but the first
        // PARTIAL_HASH_SIZE bytes are identical regardless of the trailing
        // signature, so `p_hash` works for both cases.

        for descriptor in firmwares {
            if let Some(expected) = &descriptor.decrypted_partial_hash
                && *expected == p_hash
            {
                let ec = descriptor.crypto_identifier;
                return Some(IdentifiedFirmware {
                    descriptor,
                    state: FirmwareState::Decrypted,
                    exact_match: false,
                    effective_crypto: ec,
                });
            }
        }
    }

    // ── Pass 3: trial decryption with user keys ─────────────────────
    //
    // If the firmware wasn't identified by any hash, try decrypting it
    // with every available key and matching the decrypted result.  This
    // handles encrypted firmware whose specific encrypted hash is not in
    // the database — most commonly `DynIV` firmware where the random IV
    // makes each encryption unique.
    //
    // To avoid redundant work, we collect unique `CryptoIdentifiers` from
    // the database, find a matching user key for each, decrypt once per
    // unique key, and then match the decrypted result against all
    // descriptors that share that crypto identifier.
    if let Some(keys) = keys
        && let Some(result) = identify_by_trial_decryption(data, firmwares, keys)
    {
        return Some(result);
    }

    None
}

/// Collects unique [`CryptoKey`]s that both appear in the firmware
/// database and are available in the user's key set, then trial-decrypts
/// the data with each one and attempts to match the result.
fn identify_by_trial_decryption(
    data: &[u8],
    firmwares: &'static [FirmwareDescriptor],
    keys: &[CryptoKey],
) -> Option<IdentifiedFirmware> {
    // Collect unique crypto identifiers from the database and pair each
    // with the first matching user key.  We use a Vec rather than a
    // HashMap because the number of unique identifiers is very small.
    let mut tried: Vec<&crate::crypto::CryptoIdentifier> = Vec::new();

    for descriptor in firmwares {
        let ident = &descriptor.crypto_identifier;

        // Already tried this identifier?
        if tried.contains(&ident) {
            continue;
        }
        tried.push(ident);

        // Do we have a matching key?
        let Some(key) = CryptoKey::find_by_identifier(keys, ident) else {
            continue;
        };

        // Attempt decryption — skip silently on failure (wrong key,
        // data too short, unaligned, etc.).
        let Ok(decrypted) = decrypt_firmware(data, &key) else {
            continue;
        };

        if decrypted.is_empty() {
            continue;
        }

        // ── Exact match against decrypted hashes ────────────────
        let dec_hash = sha1_hash(&decrypted);

        // For `DynIV` the decrypted output is [firmware][RSA sig (256 B)].
        // The database hash covers only the firmware without the sig.
        let dec_hash_stripped = if ident.method == CryptoMethod::AesCTR128DynIv {
            decrypted.len().checked_sub(RSA_SIG_SIZE).and_then(|end| decrypted.get(..end)).map(sha1_hash)
        } else {
            None
        };

        for fw in firmwares {
            if fw.crypto_identifier != *ident {
                continue;
            }

            if let Some(expected) = &fw.decrypted_hash {
                if *expected == dec_hash {
                    return Some(IdentifiedFirmware {
                        descriptor: fw,
                        state: FirmwareState::Encrypted,
                        exact_match: true,
                        effective_crypto: *ident,
                    });
                }

                if let Some(stripped) = &dec_hash_stripped
                    && *expected == *stripped
                {
                    return Some(IdentifiedFirmware {
                        descriptor: fw,
                        state: FirmwareState::Encrypted,
                        exact_match: true,
                        effective_crypto: *ident,
                    });
                }
            }
        }

        // ── Partial hash fallback on decrypted data ─────────────
        //
        // Unlike the exact-hash pass above, partial matching is not
        // restricted to the same crypto identifier.  The decrypted
        // vector table is identical regardless of which encryption
        // method produced the ciphertext, so a firmware encrypted with
        // a different method (e.g. static-CTR v2 export of a DynIV
        // firmware) can still be identified here.
        //
        // The effective crypto is the identifier that actually decrypted
        // the file, which may differ from the descriptor's native one.
        if let Some(p_hash) = partial_hash(&decrypted) {
            for fw in firmwares {
                if let Some(expected) = &fw.decrypted_partial_hash
                    && *expected == p_hash
                {
                    return Some(IdentifiedFirmware {
                        descriptor: fw,
                        state: FirmwareState::Encrypted,
                        exact_match: false,
                        effective_crypto: *ident,
                    });
                }
            }
        }
    }

    None
}
