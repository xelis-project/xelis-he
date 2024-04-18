use chacha20poly1305::{
    aead::{Aead, Payload},
    AeadInPlace, ChaCha20Poly1305, KeyInit,
};
use curve25519_dalek::ristretto::CompressedRistretto;
use sha3::Digest;
use zeroize::Zeroize;

use crate::{
    elgamal::{PedersenOpening, H},
    CipherFormatError, ElGamalCiphertext, ElGamalSecretKey,
};

pub(crate) type AEADKey = chacha20poly1305::Key;
pub(crate) type KDF = sha3::Sha3_256;

/// Every transfer has its associated secret key, derived from the shared secret.
/// We never use a key twice, then. We can reuse the same nonce everytime.
const NONCE: &[u8; 12] = b"xelis-crypto";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AeCipher(pub Vec<u8>);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize)] // zeroize
pub struct PlaintextData(pub Vec<u8>);

/// See [`derive_aead_key`].
pub(crate) fn derive_aead_key_from_opening(opening: &PedersenOpening) -> AEADKey {
    derive_aead_key(&(opening.as_scalar() * &*H).compress())
}
/// See [`derive_aead_key`].
pub(crate) fn derive_aead_key_from_ct(
    sk: &ElGamalSecretKey,
    ciphertext: &ElGamalCiphertext,
) -> AEADKey {
    derive_aead_key(&(sk.as_scalar() * ciphertext.handle().as_point()).compress())
}

/// During encryption, we know the opening `r`, so this needs to be called with `r * H`.
/// During decryption, we don't have to find `r`, we can just use `s * D` which is equal to `r * H` with our ciphertext.
pub(crate) fn derive_aead_key(point: &CompressedRistretto) -> AEADKey {
    let mut hash = KDF::new();
    hash.update(point.as_bytes());
    hash.finalize()
}

impl AeCipher {
    /// Warning: keys should not be reused
    pub(crate) fn decrypt_in_place(mut self, key: &AEADKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key);
        c.decrypt_in_place(NONCE.into(), &[], &mut self.0)
            .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(self.0))
    }

    /// Warning: keys should not be reused
    pub(crate) fn decrypt(&self, key: &AEADKey) -> Result<PlaintextData, CipherFormatError> {
        let c = ChaCha20Poly1305::new(&key);
        let res = c.decrypt(
            NONCE.into(),
            Payload {
                msg: &self.0,
                aad: &[],
            },
        )
        .map_err(|_| CipherFormatError)?;

        Ok(PlaintextData(res))
    }
}

impl PlaintextData {
    /// Warning: keys should not be reused
    pub(crate) fn encrypt_in_place(mut self, key: &AEADKey) -> AeCipher {
        let c = ChaCha20Poly1305::new(&key);
        c.encrypt_in_place(NONCE.into(), &[], &mut self.0)
            .expect("unreachable (unsufficient capacity on a vec)");

        AeCipher(self.0)
    }
}
