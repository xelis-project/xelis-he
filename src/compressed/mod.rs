use crate::elgamal;
use bytemuck::{Pod, Zeroable};
use curve25519_dalek::ristretto::CompressedRistretto;
use thiserror::Error;

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct PedersenCommitment(pub [u8; 32]);

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("invalid format")]
pub struct DecompressionError;

impl elgamal::PedersenCommitment {
    pub fn compress(&self) -> PedersenCommitment {
        PedersenCommitment(self.as_point().compress().to_bytes())
    }
}

impl PedersenCommitment {
    pub fn decompress(&self) -> Result<elgamal::PedersenCommitment, DecompressionError> {
        Ok(elgamal::PedersenCommitment::from_point(
            CompressedRistretto::from_slice(&self.0).map_err(|_| DecompressionError)?
            .decompress()
            .ok_or(DecompressionError)?
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct ElGamalCiphertext(pub [[u8; 32]; 2]);

impl elgamal::ElGamalCiphertext {
    pub fn compress(&self) -> ElGamalCiphertext {
        ElGamalCiphertext([
            self.commitment().as_point().compress().to_bytes(),
            self.handle().as_point().compress().to_bytes(),
        ])
    }
}

impl ElGamalCiphertext {
    pub fn decompress(&self) -> Result<elgamal::ElGamalCiphertext, DecompressionError> {
        Ok(elgamal::ElGamalCiphertext::new(
            PedersenCommitment(self.0[0]).decompress()?,
            DecryptHandle(self.0[1]).decompress()?,
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct ElGamalPubkey(pub [u8; 32]);

impl elgamal::ElGamalPubkey {
    pub fn compress(&self) -> ElGamalPubkey {
        ElGamalPubkey(self.as_point().compress().to_bytes())
    }
}

impl ElGamalPubkey {
    pub fn decompress(&self) -> Result<elgamal::ElGamalPubkey, DecompressionError> {
        Ok(elgamal::ElGamalPubkey::from_point(
            CompressedRistretto::from_slice(&self.0)
            .map_err(|_| DecompressionError)?
            .decompress()
            .ok_or(DecompressionError)?
        ))
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug, Pod, Zeroable)]
#[repr(transparent)]
pub struct DecryptHandle(pub [u8; 32]);

impl elgamal::DecryptHandle {
    pub fn compress(&self) -> DecryptHandle {
        DecryptHandle(self.as_point().compress().to_bytes())
    }
}

impl DecryptHandle {
    pub fn decompress(&self) -> Result<elgamal::DecryptHandle, DecompressionError> {
        Ok(elgamal::DecryptHandle::from_point(
            CompressedRistretto::from_slice(&self.0)
            .map_err(|_| DecompressionError)?
            .decompress()
            .ok_or(DecompressionError)?
        ))
    }
}
