use chacha20::{
    cipher::{KeyIvInit, StreamCipher}, ChaCha20
};
use curve25519_dalek::ristretto::CompressedRistretto;
use sha3::Digest;
use zeroize::Zeroize;

use crate::{
    compressed::CompressedHandle,
    elgamal::{PedersenOpening, H},
    CipherFormatError,
    DecryptHandle,
    ElGamalPubkey,
    ElGamalSecretKey,
    Role
};

pub(crate) type KDF = sha3::Sha3_256;

/// Every transfer has its associated secret key, derived from the shared secret.
/// We never use a key twice, then. We can reuse the same nonce everytime.
const NONCE: &[u8; 12] = b"xelis-crypto";

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct AeCipher(pub Vec<u8>);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Zeroize)] // zeroize
pub struct PlaintextData(pub Vec<u8>);

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct ExtraData {
    cipher: AeCipher,
    sender_handle: CompressedHandle,
    receiver_handle: CompressedHandle,
}

type SharedKey = [u8; 32];

impl PlaintextData {
    /// Warning: keys should not be reused
    pub fn encrypt_in_place(mut self, key: &SharedKey) -> AeCipher {
        let mut c = ChaCha20::new(key.into(), NONCE.into());
        c.apply_keystream(&mut self.0);

        AeCipher(self.0)
    }
}

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_opening(opening: &PedersenOpening) -> SharedKey {
    derive_shared_key(&(opening.as_scalar() * &*H).compress())
}

/// During encryption, we know the opening `r`, so this needs to be called with `r * H`.
/// During decryption, we don't have to find `r`, we can just use `s * D` which is equal to `r * H` with our ciphertext.
pub fn derive_shared_key(point: &CompressedRistretto) -> SharedKey {
    let mut hash = KDF::new();
    hash.update(point.as_bytes());
    hash.finalize().into()
}

/// See [`derive_shared_key`].
pub fn derive_shared_key_from_handle(
    sk: &ElGamalSecretKey,
    handle: &DecryptHandle,
) -> SharedKey {
    derive_shared_key(&(sk.as_scalar() * handle.as_point()).compress())
}

impl ExtraData {
    // Create a new extra data that will encrypt the message for receiver & sender keys.
    // Both will be able to decrypt it.
    pub fn new(data: PlaintextData, sender: &ElGamalPubkey, receiver: &ElGamalPubkey) -> Self {
        // Generate a new opening (randomness r)
        let opening = PedersenOpening::generate_new();
        // From the randomness, derive the opening it to get the shared key
        // that will be used for encrypt/decrypt
        let k = derive_shared_key_from_opening(&opening);
        Self {
            // Encrypt the cipher using the shared key
            cipher: data.encrypt_in_place(&k),
            // Create a handle for the sender so he can decrypt the message later
            // SH = sender PK * r
            // Because SK is invert of PK, we can decrypt it by doing SH * SK 
            sender_handle: sender.decrypt_handle(&opening).compress(),
            // Same for the receiver
            // RH = receiver PK * r
            receiver_handle: receiver.decrypt_handle(&opening).compress(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.cipher.0);
        bytes.extend_from_slice(&self.sender_handle.0);
        bytes.extend_from_slice(&self.receiver_handle.0);
        bytes
    }

    pub fn decrypt_in_place(self, sk: &ElGamalSecretKey, role: Role) -> Result<PlaintextData, CipherFormatError> {
        let handle = match role {
            Role::Receiver => self.receiver_handle,
            Role::Sender => self.sender_handle,
        };

        let h = handle.decompress().map_err(|_| CipherFormatError)?;
        let key = derive_shared_key_from_handle(sk, &h);

        let mut c = ChaCha20::new(&key.into(), NONCE.into());
        let mut data = self.cipher.0;
        c.apply_keystream(&mut data);
        Ok(PlaintextData(data))
    }
}