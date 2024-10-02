use crate::{compressed, Hash};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar, traits::IsIdentity};
use merlin::Transcript;
use thiserror::Error;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum TranscriptError {
    #[error("point should not be the identity")]
    IdentityPoint,
}

pub trait ProtocolTranscript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    fn append_pubkey(&mut self, label: &'static [u8], point: &compressed::CompressedPubkey);
    fn append_ciphertext(&mut self, label: &'static [u8], point: &compressed::CompressedCiphertext);
    fn append_commitment(&mut self, label: &'static [u8], point: &compressed::CompressedCommitment);
    fn append_handle(&mut self, label: &'static [u8], point: &compressed::CompressedHandle);
    fn append_hash(&mut self, label: &'static [u8], point: &Hash);

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), TranscriptError>;

    fn equality_proof_domain_separator(&mut self);
    fn new_commitment_eq_proof_domain_separator(&mut self);
    fn transfer_proof_domain_separator(&mut self);
    fn burn_proof_domain_separator(&mut self);
    fn multisig_proof_domain_separator(&mut self);
    fn ciphertext_validity_proof_domain_separator(&mut self);
}

impl ProtocolTranscript for Transcript {
    fn append_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.append_message(label, scalar.as_bytes());
    }

    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }

    fn append_pubkey(&mut self, label: &'static [u8], pubkey: &compressed::CompressedPubkey) {
        self.append_message(label, bytemuck::bytes_of(pubkey));
    }

    fn append_ciphertext(&mut self, label: &'static [u8], ciphertext: &compressed::CompressedCiphertext) {
        self.append_message(label, bytemuck::bytes_of(ciphertext));
    }

    fn append_commitment(&mut self, label: &'static [u8], commitment: &compressed::CompressedCommitment) {
        self.append_message(label, bytemuck::bytes_of(commitment));
    }

    fn append_handle(&mut self, label: &'static [u8], handle: &compressed::CompressedHandle) {
        self.append_message(label, bytemuck::bytes_of(handle));
    }

    fn append_hash(&mut self, label: &'static [u8], point: &Hash) {
        self.append_message(label, &point.0)
    }

    fn validate_and_append_point(
        &mut self,
        label: &'static [u8],
        point: &CompressedRistretto,
    ) -> Result<(), TranscriptError> {
        if point.is_identity() {
            Err(TranscriptError::IdentityPoint)
        } else {
            self.append_message(label, point.as_bytes());
            Ok(())
        }
    }

    // domain separators

    fn new_commitment_eq_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"new-commitment-proof");
    }

    fn transfer_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"transfer-proof");
    }

    fn burn_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"burn-proof");
    }

    fn multisig_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"multisig-proof");
    }

    fn equality_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"equality-proof");
    }

    fn ciphertext_validity_proof_domain_separator(&mut self) {
        self.append_message(b"dom-sep", b"validity-proof");
    }
}
