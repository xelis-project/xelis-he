use crate::{
    compressed, elgamal::*, transcript::ProtocolTranscript, TransferProofGenerationError,
    TransferProofVerificationError,
};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G,
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
    traits::{IsIdentity, MultiscalarMul, VartimeMultiscalarMul},
};
use rand::rngs::OsRng;

use merlin::Transcript;
use zeroize::Zeroize;

/// Proof that a commitment and ciphertext are equal.
#[allow(non_snake_case)]
struct CommitmentEqProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    Y_2: CompressedRistretto,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,
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
    pub fn verify(
        &self,
        source_pubkey: &ElGamalPubkey,
        source_ciphertext: &ElGamalCiphertext,
        destination_commitment: &PedersenCommitment,
        transcript: &mut Transcript,
    ) -> Result<(), TransferProofVerificationError> {
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
            .ok_or(TransferProofVerificationError::CommitmentEqProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(TransferProofVerificationError::CommitmentEqProof)?;
        let Y_2 = self
            .Y_2
            .decompress()
            .ok_or(TransferProofVerificationError::CommitmentEqProof)?;

        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                &self.z_s,           // z_s
                &(-&c),              // -c
                &(-&Scalar::one()),  // -identity
                &(&w * &self.z_x),   // w * z_x
                &(&w * &self.z_s),   // w * z_s
                &(&w_negated * &c),  // -w * c
                &w_negated,          // -w
                &(&ww * &self.z_x),  // ww * z_x
                &(&ww * &self.z_r),  // ww * z_r
                &(&ww_negated * &c), // -ww * c
                &ww_negated,         // -ww
            ],
            vec![
                P_source,      // P_source
                &(*H),         // H
                &Y_0,          // Y_0
                &G,            // G
                D_source,      // D_source
                C_source,      // C_source
                &Y_1,          // Y_1
                &G,            // G
                &(*H),         // H
                C_destination, // C_destination
                &Y_2,          // Y_2
            ],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(TransferProofVerificationError::CommitmentEqProof.into())
        }
    }
}

#[allow(non_snake_case)]
struct CiphertextValidityProof {
    Y_0: CompressedRistretto,
    Y_1: CompressedRistretto,
    z_r: Scalar,
    z_x: Scalar,
}

#[allow(non_snake_case)]
impl CiphertextValidityProof {
    pub fn new(
        destination_pubkey: &ElGamalPubkey,
        amount: u64,
        opening: &PedersenOpening,
        transcript: &mut Transcript,
    ) -> Self {
        transcript.ciphertext_validity_proof_domain_separator();

        let P_dest = destination_pubkey.as_point();

        let x = Scalar::from(amount);
        let r = opening.as_scalar();

        let mut y_r = Scalar::random(&mut OsRng);
        let mut y_x = Scalar::random(&mut OsRng);

        let Y_0 = RistrettoPoint::multiscalar_mul(vec![&y_r, &y_x], vec![&(*H), &G]).compress();
        let Y_1 = (&y_r * P_dest).compress();

        transcript.append_point(b"Y_0", &Y_0);
        transcript.append_point(b"Y_1", &Y_1);

        let c = transcript.challenge_scalar(b"c");
        transcript.challenge_scalar(b"w");

        // masked message and opening
        let z_r = &(&c * r) + &y_r;
        let z_x = &(&c * &x) + &y_x;

        y_r.zeroize();
        y_x.zeroize();

        Self { Y_0, Y_1, z_r, z_x }
    }

    pub fn verify(
        &self,
        commitment: &PedersenCommitment,
        dest_pubkey: &ElGamalPubkey,
        dest_handle: &DecryptHandle,
        transcript: &mut Transcript,
    ) -> Result<(), TransferProofVerificationError> {
        transcript.ciphertext_validity_proof_domain_separator();

        transcript.validate_and_append_point(b"Y_0", &self.Y_0)?;
        transcript.validate_and_append_point(b"Y_1", &self.Y_1)?;

        let c = transcript.challenge_scalar(b"c");
        let w = transcript.challenge_scalar(b"w");

        let w_negated = -&w;

        let Y_0 = self
            .Y_0
            .decompress()
            .ok_or(TransferProofVerificationError::CiphertextValidityProof)?;
        let Y_1 = self
            .Y_1
            .decompress()
            .ok_or(TransferProofVerificationError::CiphertextValidityProof)?;

        let P_dest = dest_pubkey.as_point();

        let C = commitment.as_point();
        let D_dest = dest_handle.as_point();

        // z_r*H + z_x*G = c*C + Y_0 and z_r*P_1 = c*D_1 + Y_1
        // <=> (z_r*H + z_x*G - c*C - Y_0) + w*(z_r*P_1 - c*D_1 - Y_1) = 0
        let check = RistrettoPoint::vartime_multiscalar_mul(
            vec![
                &self.z_r,          // z_r
                &self.z_x,          // z_x
                &(-&c),             // -c
                &-(&Scalar::one()), // -identity
                &(&w * &self.z_r),  // w * z_r
                &(&w_negated * &c), // -w * c
                &w_negated,         // -w
            ],
            vec![
                &(*H),  // H
                &G,     // G
                C,      // C
                &Y_0,   // Y_0
                P_dest, // P_dest
                D_dest, // D_dest
                &Y_1,   // Y_1
            ],
        );

        if check.is_identity() {
            Ok(())
        } else {
            Err(TransferProofVerificationError::CiphertextValidityProof)
        }
    }
}

pub struct Transfer {
    pub(crate) amount_commitment: compressed::PedersenCommitment,
    pub(crate) amount_sender_handle: compressed::DecryptHandle,
    pub(crate) amount_receiver_handle: compressed::DecryptHandle,
    ct_validity_proof: CiphertextValidityProof,
    range_proof: RangeProof,
    new_source_commitment: compressed::PedersenCommitment,
    new_commitment_eq_proof: CommitmentEqProof,
}

impl Transfer {
    fn prepare_transcript(
        amount_commitment: &compressed::PedersenCommitment,
        amount_sender_handle: &compressed::DecryptHandle,
        amount_receiver_handle: &compressed::DecryptHandle,
        source_pubkey: &compressed::ElGamalPubkey,
        dest_pubkey: &compressed::ElGamalPubkey,
        new_source_commitment: &compressed::PedersenCommitment,
    ) -> Transcript {
        let mut transcript = Transcript::new(b"transfer-proof");
        transcript.append_commitment(b"amount_commitment", amount_commitment);
        transcript.append_handle(b"amount_sender_handle", amount_sender_handle);
        transcript.append_handle(b"amount_receiver_handle", amount_receiver_handle);
        transcript.append_pubkey(b"source_pubkey", source_pubkey);
        transcript.append_pubkey(b"dest_pubkey", dest_pubkey);
        transcript.append_commitment(b"new_source_commitment", &new_source_commitment);
        transcript
    }

    pub fn new(
        source_current_ciphertext: &compressed::ElGamalCiphertext,
        source_current_balance: u64,
        amount: u64,
        source_keypair: &ElGamalKeypair,
        dest_pubkey: &compressed::ElGamalPubkey,
    ) -> Result<Self, TransferProofGenerationError> {
        let d_dest_pubkey = dest_pubkey.decompress().unwrap();
        let d_source_current_ciphertext = source_current_ciphertext.decompress().unwrap();

        let amount_opening = PedersenOpening::generate_new();
        let amount_commitment = PedersenCommitment::new_with_opening(amount, &amount_opening);
        let amount_sender_handle = source_keypair.pubkey().decrypt_handle(&amount_opening);
        let amount_receiver_handle = d_dest_pubkey.decrypt_handle(&amount_opening);

        let amount_commitment_pod = amount_commitment.compress();
        let amount_sender_handle_pod = amount_sender_handle.compress();
        let amount_receiver_handle_pod = amount_receiver_handle.compress();

        let source_new_balance = source_current_balance
            .checked_sub(amount)
            .ok_or(TransferProofGenerationError::InsufficientFunds)?;

        // make a new comitment for the remaining balance in source
        let (new_source_commitment, source_opening) = PedersenCommitment::new(source_new_balance);
        let new_source_commitment_pod = new_source_commitment.compress();

        let mut transcript = Self::prepare_transcript(
            &amount_commitment_pod,
            &amount_sender_handle_pod,
            &amount_receiver_handle_pod,
            &source_keypair.pubkey().compress(),
            &dest_pubkey,
            &new_source_commitment_pod,
        );

        let new_source_ciphertext = &d_source_current_ciphertext
            - &ElGamalCiphertext::new(amount_commitment, amount_sender_handle);

        let new_commitment_eq_proof = CommitmentEqProof::new(
            source_keypair,
            &new_source_ciphertext,
            &source_opening,
            source_new_balance,
            &mut transcript,
        );

        let ct_validity_proof =
            CiphertextValidityProof::new(&d_dest_pubkey, amount, &amount_opening, &mut transcript);
        let bp_gens = BulletproofGens::new(64, 2);
        let pc_gens = PedersenGens::default();

        let (range_proof, _commitments) = RangeProof::prove_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &[source_new_balance, amount],
            &[source_opening.as_scalar(), amount_opening.as_scalar()],
            64,
        )?;

        Ok(Self {
            amount_commitment: amount_commitment_pod,
            amount_sender_handle: amount_sender_handle_pod,
            amount_receiver_handle: amount_receiver_handle_pod,
            ct_validity_proof,
            range_proof,
            new_source_commitment: new_source_commitment_pod,
            new_commitment_eq_proof,
        })
    }

    pub fn verify(
        &self,
        source_pubkey: &compressed::ElGamalPubkey,
        source_current_ciphertext: &compressed::ElGamalCiphertext,
        dest_pubkey: &compressed::ElGamalPubkey,
    ) -> Result<(), TransferProofVerificationError> {
        let source_pubkey_u = source_pubkey.decompress()?;
        let source_current_ciphertext_u = source_current_ciphertext.decompress()?;
        let dest_pubkey_u = dest_pubkey.decompress()?;

        let mut transcript = Self::prepare_transcript(
            &self.amount_commitment,
            &self.amount_sender_handle,
            &self.amount_receiver_handle,
            &source_pubkey,
            &dest_pubkey,
            &self.new_source_commitment,
        );

        let amount_commitment = self.amount_commitment.decompress()?;
        let amount_sender_handle = self.amount_sender_handle.decompress()?;
        let amount_receiver_handle = self.amount_receiver_handle.decompress()?;
        let new_source_commitment = self.new_source_commitment.decompress()?;

        let new_source_ciphertext = &source_current_ciphertext_u
            - &ElGamalCiphertext::new(amount_commitment.clone(), amount_sender_handle);

        self.new_commitment_eq_proof.verify(
            &source_pubkey_u,
            &new_source_ciphertext,
            &new_source_commitment,
            &mut transcript,
        )?;

        let bp_gens = BulletproofGens::new(64, 2);
        let pc_gens = PedersenGens::default();

        self.ct_validity_proof.verify(
            &amount_commitment,
            &dest_pubkey_u,
            &amount_receiver_handle,
            &mut transcript,
        )?;

        self.range_proof.verify_multiple(
            &bp_gens,
            &pc_gens,
            &mut transcript,
            &[
                new_source_commitment.as_point().compress(),
                amount_commitment.as_point().compress(),
            ],
            64,
        )?;

        Ok(())
    }
}
