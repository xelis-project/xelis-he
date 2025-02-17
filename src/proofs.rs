use crate::{
    elgamal::{DecryptHandle, ElGamalCiphertext, PedersenCommitment, PedersenOpening, H},
    transcript::ProtocolTranscript,
    ElGamalKeypair, ElGamalPubkey, ProofVerificationError,
};
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use lazy_static::lazy_static;
use merlin::Transcript;
use rand::rngs::OsRng;
use std::iter;
use thiserror::Error;
use zeroize::Zeroize;

lazy_static! {
    pub static ref BP_GENS: BulletproofGens = BulletproofGens::new(64, 64);
    pub static ref PC_GENS: PedersenGens = PedersenGens::default();
}

/// Proof that a commitment and ciphertext are equal.
#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CommitmentEqProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    Y_2: CompressedRistretto,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,
}

#[derive(Error, Debug)]
#[error("batch multiscalar mul returned non identity point")]
pub struct MultiscalarMulVerificationError;

#[derive(Default)]
pub struct BatchCollector {
    dynamic_scalars: Vec<Scalar>,
    dynamic_points: Vec<RistrettoPoint>,
    g_scalar: Scalar,
    h_scalar: Scalar,
}

impl BatchCollector {
    pub fn verify(&self) -> Result<(), MultiscalarMulVerificationError> {
        let mega_check = RistrettoPoint::vartime_multiscalar_mul(
            self.dynamic_scalars
                .iter()
                .chain(iter::once(&self.g_scalar))
                .chain(iter::once(&self.h_scalar)),
            self.dynamic_points
                .iter()
                .cloned()
                .chain(iter::once(G))
                .chain(iter::once(*H)),
        );

        if mega_check.is_identity().into() {
            Ok(())
        } else {
            Err(MultiscalarMulVerificationError)
        }
    }
}

#[allow(non_snake_case)]
impl CommitmentEqProof {
    // warning: caller must make sure not to forget to hash the public key, ciphertext, commitment in the transcript as it is not done here
    pub fn new(
        source_keypair: &ElGamalKeypair,
        source_ciphertext: &ElGamalCiphertext,
        opening: &PedersenOpening,
        amount: u64,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_keypair.pubkey().as_point();
        let D_source = source_ciphertext.handle().as_point();

        let s = source_keypair.secret().as_scalar();
        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        // generate random masking factors that also serves as nonces
        let mut y_s = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);
        let mut y_r = Scalar::random(&mut OsRng);

        let Y_0 = (&y_s * P_source).compress();
        let Y_1 =
            RistrettoPoint::multiscalar_mul(vec![&y_x, &y_s], vec![&(G), D_source]).compress();
        let Y_2 = RistrettoPoint::multiscalar_mul(vec![&y_x, &y_r], vec![&(G), &(*H)]).compress();

        // record masking factors in the transcript
        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // compute the masked values
        let z_s = &(&c * s) + &y_s;
        let z_x = &(&c * &x) + &y_x;
        let z_r = &(&c * r) + &y_r;

        // zeroize random scalars
        y_s.zeroize();
        y_x.zeroize();
        y_r.zeroize();

        Self {
            Y_0,
            Y_1,
            Y_2,
            z_s,
            z_x,
            z_r,
        }
    }

    pub fn pre_verify(
        &self,
        source_pubkey: &ElGamalPubkey,
        source_ciphertext: &ElGamalCiphertext,
        destination_commitment: &PedersenCommitment,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.equality_proof_domain_separator();

        // extract the relevant scalar and Ristretto points from the inputs
        let P_source = source_pubkey.as_point();
        let C_source = source_ciphertext.commitment().as_point();
        let D_source = source_ciphertext.handle().as_point();
        let C_destination = destination_commitment.as_point();

        // include Y_0, Y_1, Y_2 to transcript and extract challenges
        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w"); // w used for batch verification
        let ww = &w * &w;

        let w_negated = -&w;
        let ww_negated = -&ww;

        // check that the required algebraic condition holds
        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(ProofVerificationError::CommitmentEqProof)?;

        let batch_factor = Scalar::random(&mut OsRng);

        // w * z_x * G + ww * z_x * G
        batch_collector.g_scalar += (w * self.z_x + ww * self.z_x) * batch_factor;
        // -c * H + ww * z_r * H
        batch_collector.h_scalar += (-c + ww * self.z_r) * batch_factor;

        batch_collector.dynamic_scalars.extend(
            [
                self.z_s,       // z_s
                -Scalar::ONE,   // -identity
                w * self.z_s,   // w * z_s
                w_negated * c,  // -w * c
                w_negated,      // -w
                ww_negated * c, // -ww * c
                ww_negated,     // -ww
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            P_source,      // P_source
            &Y_0,          // Y_0
            D_source,      // D_source
            C_source,      // C_source
            &Y_1,          // Y_1
            C_destination, // C_destination
            &Y_2,          // Y_2
        ]);

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.Y_0.to_bytes());
        bytes.extend_from_slice(&self.Y_1.to_bytes());
        bytes.extend_from_slice(&self.Y_2.to_bytes());
        bytes.extend_from_slice(&self.z_s.to_bytes());
        bytes.extend_from_slice(&self.z_x.to_bytes());
        bytes.extend_from_slice(&self.z_r.to_bytes());
        bytes
    }
}

#[allow(non_snake_case)]
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct CiphertextValidityProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    Y_2: CompressedRistretto,
    z_r: Scalar,
    z_x: Scalar,
}

#[allow(non_snake_case)]
impl CiphertextValidityProof {
    pub fn new(
        destination_pubkey: &ElGamalPubkey,
        source_pubkey: &ElGamalPubkey,
        amount: u64,
        opening: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.ciphertext_validity_proof_domain_separator();

        let P_dest = destination_pubkey.as_point();
        let P_source = source_pubkey.as_point();

        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        let mut y_r = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);

        let Y_0 = RistrettoPoint::multiscalar_mul(vec![&y_r, &y_x], vec![&(*H), &G]).compress();
        let Y_1 = (&y_r * P_dest).compress();
        let Y_2 =  (&y_r * P_source).compress();

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);
        transcript.append_point(b"Y_2", &Y_2);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        y_r.zeroize();
        y_x.zeroize();

        Self { Y_0, Y_1, Y_2, z_r, z_x }
    }

    pub fn pre_verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &ElGamalPubkey,
        source_pubkey: &ElGamalPubkey,
        dest_handle: &DecryptHandle,
        source_handle: &DecryptHandle,
        transcript: &mut Transcript,
        batch_collector: &mut BatchCollector,
    ) -> Result<(), ProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;
        transcript.validate_and_append_point(b"Y_2", &self.Y_2)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");

        let w_negated = -&w;

        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(ProofVerificationError::CiphertextValidityProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(ProofVerificationError::CiphertextValidityProof)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(ProofVerificationError::CiphertextValidityProof)?;

        let P_dest = dest_pubkey.as_point();
        let P_source = source_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();
        let D_source = source_handle.as_point();

        let batch_factor = Scalar::random(&mut OsRng);

        // z_x * G
        batch_collector.g_scalar += self.z_x * batch_factor;
        // z_r * H
        batch_collector.h_scalar += self.z_r * batch_factor;

        let w_z_r = w * self.z_r;
        let w_negated_c = w_negated * c;

        batch_collector.dynamic_scalars.extend(
            [
                -c,            // -c
                -Scalar::ONE,  // -identity
                w_z_r,  // w * z_r
                w_negated_c, // -w * c
                w_negated,     // -w
                w * w_z_r,       // w * z_r
                w * w_negated_c, // -w * c
                w * w_negated,   // -w
            ]
            .map(|s| s * batch_factor),
        );
        batch_collector.dynamic_points.extend([
            C,      // C
            &Y_0,   // Y_0
            P_dest, // P_dest
            D_dest, // D_dest
            &Y_1,   // Y_1
            P_source, // P_source
            D_source, // D_source
            &Y_2,     // Y_2
        ]);

        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.Y_0.to_bytes());
        bytes.extend_from_slice(&self.Y_1.to_bytes());
        bytes.extend_from_slice(&self.Y_2.to_bytes());
        bytes.extend_from_slice(&self.z_r.to_bytes());
        bytes.extend_from_slice(&self.z_x.to_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eq_proof() {
        let mut t = Transcript::new(b"test_eq_proof");
        let keypair = ElGamalKeypair::keygen();

        // Generate our initial balance
        let balance = 100u64;
        let source_balance = keypair.pubkey().encrypt(balance);

        // Generate the ciphertext
        let amount = 5u64;
        let opening = PedersenOpening::generate_new();
        let ciphertext = keypair.pubkey().encrypt_with_opening(amount, &opening);

        // Commitment of the final balance using the same Opening
        let commitment = PedersenCommitment::new_with_opening(balance - amount, &opening);

        // Compute the final balance
        let final_balance = source_balance - &ciphertext;

        // Create the proof
        let proof = CommitmentEqProof::new(&keypair, &final_balance, &opening, balance - amount, &mut t);

        // Regenerate a new transcript for the verification for testing
        let mut t = Transcript::new(b"test_eq_proof");
        let mut batch_collector = BatchCollector::default();
        let res = proof.pre_verify(
            keypair.pubkey(),
            &final_balance,
            &commitment,
            &mut t,
            &mut batch_collector,
        );
        assert!(res.is_ok());
        assert!(batch_collector.verify().is_ok());
    }

    #[test]
    fn test_ciphertext_proof() {
        let mut t = Transcript::new(b"test_ciphertext_proof");
        let alice = ElGamalKeypair::keygen();
        let bob = ElGamalKeypair::keygen();

        // Generate the commitment
        let amount = 5u64;
        let opening = PedersenOpening::generate_new();
        let commitment = PedersenCommitment::new_with_opening(amount, &opening);

        // Create the receiver handle
        let bob_handle = bob.pubkey().decrypt_handle(&opening);
        let alice_handle = alice.pubkey().decrypt_handle(&opening);

        // Create the proof
        let proof = CiphertextValidityProof::new(bob.pubkey(), alice.pubkey(), amount, &opening, &mut t);

        // Regenerate a new transcript for the verification for testing
        let mut t = Transcript::new(b"test_ciphertext_proof");
        let mut batch_collector = BatchCollector::default();
        let res = proof.pre_verify(
            &commitment,
            bob.pubkey(),
            alice.pubkey(),
            &bob_handle,
            &alice_handle,
            &mut t,
            &mut batch_collector,
        );
        assert!(res.is_ok());
        assert!(batch_collector.verify().is_ok());
    }
}