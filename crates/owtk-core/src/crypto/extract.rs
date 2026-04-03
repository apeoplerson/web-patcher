use std::collections::{HashMap, HashSet};

use hex_literal::hex;

use super::sha1_hash;
use super::types::{CryptoIdentifier, CryptoKey, CryptoMethod};

/// XR (v3,v4,v6,v9), Pint (v6), Pint X (v7)
const CRYPTO_ID_ECB: CryptoIdentifier = CryptoIdentifier {
    method: CryptoMethod::AesECB128,
    key_hash: hex!("e61dcd2fa9e689a370f6a7f81b1757cf05490c94"),
    iv_hash: None,
};

/// GT (v1,v2)
pub const CRYPTO_ID_GT_CTR: CryptoIdentifier = CryptoIdentifier {
    method: CryptoMethod::AesCTR128,
    key_hash: hex!("75c88aa944d3508f985058a389d1ead4ffa03a1c"),
    iv_hash: Some(hex!("14ad78f4d9805cf8fe8cf3ac970f7d59b9fb651c")),
};

/// GT (v3)
pub const CRYPTO_ID_GT_CTR_DYN: CryptoIdentifier = CryptoIdentifier {
    method: CryptoMethod::AesCTR128DynIv,
    key_hash: hex!("3d00c1c9b3513c059723acdf66de670fa1967bf9"),
    iv_hash: None,
};

/// GTS (v4)
const CRYPTO_ID_GTS_CTR_DYN: CryptoIdentifier = CryptoIdentifier {
    method: CryptoMethod::AesCTR128DynIv,
    key_hash: hex!("3f41179e2245423f49b58ff3790b0c560eb49e9d"),
    iv_hash: None,
};

/// XRC (v5)
const CRYPTO_ID_XRC_CTR_DYN: CryptoIdentifier = CryptoIdentifier {
    method: CryptoMethod::AesCTR128DynIv,
    key_hash: hex!("e8fd6b23e5b691fcfb823dced209beddc50926ff"),
    iv_hash: None,
};

#[rustfmt::skip]
const CRYPTO_IDENTIFIERS: &[CryptoIdentifier] = &[
    CRYPTO_ID_ECB,
    CRYPTO_ID_GT_CTR,
    CRYPTO_ID_GT_CTR_DYN,
    CRYPTO_ID_GTS_CTR_DYN,
    CRYPTO_ID_XRC_CTR_DYN,
];

pub fn extract_keys_from_dump(dump: &[u8]) -> Vec<CryptoKey> {
    const KEY_SIZE: usize = 16; // AES-128 key size

    if dump.len() < KEY_SIZE {
        return Vec::new();
    }

    // Build a small set of all hashes we're looking for (key + IV hashes
    // from the known crypto identifiers).  Typically ~8 entries.
    let mut wanted: HashSet<[u8; 20]> = HashSet::new();
    for ident in CRYPTO_IDENTIFIERS {
        wanted.insert(ident.key_hash);
        if let Some(iv_hash) = &ident.iv_hash {
            wanted.insert(*iv_hash);
        }
    }

    // Scan the dump once, recording only the offsets of wanted hashes.
    let mut found: HashMap<[u8; 20], usize> = HashMap::with_capacity(wanted.len());
    for offset in 0..=dump.len() - KEY_SIZE {
        let slice = dump.get(offset..offset + KEY_SIZE).expect("offset range is within 0..=dump.len()-KEY_SIZE");
        let hash = sha1_hash(slice);
        if wanted.contains(&hash) {
            found.insert(hash, offset);
            // Early exit if we've found everything.
            if found.len() == wanted.len() {
                break;
            }
        }
    }

    let mut results = Vec::new();

    for ident in CRYPTO_IDENTIFIERS {
        let Some(&key_offset) = found.get(&ident.key_hash) else {
            continue;
        };

        let key: [u8; 16] = dump
            .get(key_offset..key_offset + KEY_SIZE)
            .expect("key offset is within bounds")
            .try_into()
            .expect("slice is exactly KEY_SIZE bytes");

        let iv = match &ident.iv_hash {
            Some(iv_hash) => {
                let Some(&iv_offset) = found.get(iv_hash) else {
                    continue;
                };
                Some(
                    dump.get(iv_offset..iv_offset + KEY_SIZE)
                        .expect("iv offset is within bounds")
                        .try_into()
                        .expect("slice is exactly KEY_SIZE bytes"),
                )
            }
            None => None,
        };

        results.push(CryptoKey { identifier: *ident, key, iv });
    }

    results
}
