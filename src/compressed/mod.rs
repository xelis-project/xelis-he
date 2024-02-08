use crate::elgamal;
use bytemuck::{Pod, Zeroable};
use curve25519_dalek::ristretto::CompressedRistretto;
use serde_derive::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompressedCommitment(pub [u8; 32]);

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("invalid format")]
pub struct DecompressionError;

impl elgamal::PedersenCommitment {
    pub fn compress(&self) -> CompressedCommitment {
        CompressedCommitment(self.as_point().compress().to_bytes())
    }
}

impl CompressedCommitment {
    pub fn as_point(&self) -> CompressedRistretto {
        CompressedRistretto(self.0)
    }

    pub fn decompress(&self) -> Result<elgamal::PedersenCommitment, DecompressionError> {
        Ok(elgamal::PedersenCommitment::from_point(
            CompressedRistretto(self.0)
                .decompress()
                .ok_or(DecompressionError)?,
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompressedCiphertext(pub [[u8; 32]; 2]);

impl elgamal::ElGamalCiphertext {
    pub fn compress(&self) -> CompressedCiphertext {
        CompressedCiphertext([
            self.commitment().as_point().compress().to_bytes(),
            self.handle().as_point().compress().to_bytes(),
        ])
    }
}

impl CompressedCiphertext {
    pub fn new(commitment: CompressedCommitment, handle: CompressedHandle) -> Self {
        Self([commitment.0, handle.0])
    }

    pub fn decompress(&self) -> Result<elgamal::ElGamalCiphertext, DecompressionError> {
        Ok(elgamal::ElGamalCiphertext::new(
            CompressedCommitment(self.0[0]).decompress()?,
            CompressedHandle(self.0[1]).decompress()?,
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompressedPubkey(pub [u8; 32]);

impl elgamal::ElGamalPubkey {
    pub fn compress(&self) -> CompressedPubkey {
        CompressedPubkey(self.as_point().compress().to_bytes())
    }
}

impl CompressedPubkey {
    pub fn decompress(&self) -> Result<elgamal::ElGamalPubkey, DecompressionError> {
        Ok(elgamal::ElGamalPubkey::from_point(
            CompressedRistretto(self.0)
                .decompress()
                .ok_or(DecompressionError)?,
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable, Serialize, Deserialize)]
#[repr(transparent)]
pub struct CompressedHandle(pub [u8; 32]);

impl elgamal::DecryptHandle {
    pub fn compress(&self) -> CompressedHandle {
        CompressedHandle(self.as_point().compress().to_bytes())
    }
}

impl CompressedHandle {
    pub fn decompress(&self) -> Result<elgamal::DecryptHandle, DecompressionError> {
        Ok(elgamal::DecryptHandle::from_point(
            CompressedRistretto(self.0)
                .decompress()
                .ok_or(DecompressionError)?,
        ))
    }
}
