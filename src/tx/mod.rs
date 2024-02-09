use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use merlin::Transcript;
use std::iter;
use thiserror::Error;

pub mod builder;

use crate::{
    compressed::{CompressedCommitment, CompressedHandle, DecompressionError},
    elgamal::ElGamalCiphertext,
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    CompressedCiphertext, CompressedPubkey, ECDLPInstance, ElGamalSecretKey,
    ProofVerificationError, Role,
};

#[derive(Error, Debug, Clone)]
pub enum VerificationError<T> {
    State(T),
    Proof(#[from] ProofVerificationError),
}

/// This trait is used by the batch verification function. It is intended to represent a virtual snapshot of the current blockchain
/// state, where the transactions can get applied in order.
pub trait BlockchainVerificationState {
    type Error;

    /// Get the balance ciphertext from an account
    fn get_account_balance(
        &self,
        account: &CompressedPubkey,
    ) -> Result<CompressedCiphertext, Self::Error>;

    /// Apply a new balance ciphertext to an account
    fn update_account_balance(
        &mut self,
        account: &CompressedPubkey,
        new_ct: CompressedCiphertext,
    ) -> Result<(), Self::Error>;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transfer {
    // pub asset: Hash,
    pub dest_pubkey: CompressedPubkey,
    // pub extra_data: Option<Vec<u8>>, // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    /// Represents the ciphertext along with `amount_sender_handle` and `amount_receiver_handle`.
    /// The opening is reused for both of the sender and receiver commitments.
    amount_commitment: CompressedCommitment,
    amount_sender_handle: CompressedHandle,
    amount_receiver_handle: CompressedHandle,
    ct_validity_proof: CiphertextValidityProof,
}

impl Transfer {
    pub fn get_ciphertext(&self, role: Role) -> CompressedCiphertext {
        let handle = match role {
            Role::Receiver => self.amount_receiver_handle,
            Role::Sender => self.amount_sender_handle,
        };

        CompressedCiphertext::new(self.amount_commitment, handle)
    }

    /// Note: this function returns an `ECDLPInstance` object, which you will need to decode.
    pub fn decrypt_amount(
        &self,
        sk: &ElGamalSecretKey,
        role: Role,
    ) -> Result<ECDLPInstance, DecompressionError> {
        Ok(sk.decrypt(&self.get_ciphertext(role).decompress()?))
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SmartContractCall {
    // pub contract: Hash,
    pub amount: u64, // TODO: change to assets
                     // pub assets: HashMap<Hash, u64>,
                     // pub params: HashMap<String, String> // TODO
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum TransactionType {
    #[serde(rename = "transfers")]
    Transfer(Vec<Transfer>),
    #[serde(rename = "burn")]
    Burn { /* asset: Hash,  */ amount: u64, },
    #[serde(rename = "call_contract")]
    CallContract(SmartContractCall),
    #[serde(rename = "deploy_contract")]
    DeployContract(String), // represent the code to deploy
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transaction {
    version: u8,
    owner: CompressedPubkey,
    data: TransactionType,
    fee: u64,
    nonce: u64,
    // signature: Signature,
    range_proof: RangeProof,
    new_source_commitment: CompressedCommitment,
    new_commitment_eq_proof: CommitmentEqProof,
}

impl Transaction {
    // get the new sender balance ciphertext
    fn get_sender_new_balance_ct(
        &self,
        source_current_balance: &ElGamalCiphertext,
    ) -> Result<ElGamalCiphertext, DecompressionError> {
        println!("bal => {:?}", source_current_balance.compress());
        let mut bal = source_current_balance - Scalar::from(self.fee);
        match &self.data {
            TransactionType::Transfer(transfers) => {
                for transfer in transfers {
                    bal -= transfer.get_ciphertext(Role::Sender).decompress()?;
                }
            }
            TransactionType::Burn { amount, .. } => bal -= Scalar::from(*amount),
            TransactionType::CallContract(SmartContractCall { amount }) => {
                bal -= Scalar::from(*amount)
            }
            TransactionType::DeployContract(_) => todo!(),
        }

        Ok(bal)
    }

    fn prepare_transcript(
        version: u8,
        owner: &CompressedPubkey,
        fee: u64,
        nonce: u64,
        new_source_commitment: &CompressedCommitment,
    ) -> Transcript {
        let mut transcript = Transcript::new(b"transaction-proof");
        transcript.append_u64(b"version", version.into());
        transcript.append_pubkey(b"owner", owner);
        transcript.append_u64(b"fee", fee);
        transcript.append_u64(b"nonce", nonce);
        transcript.append_commitment(b"new_source_commitment", new_source_commitment);
        transcript
    }

    // internal, does not verify the range proof
    // returns (transcript, commitments for range proof, new source ct)
    fn pre_verify(
        &self,
        source_current_ciphertext: &CompressedCiphertext,
    ) -> Result<(Transcript, Vec<CompressedRistretto>, CompressedCiphertext), ProofVerificationError>
    {
        let owner = self.owner.decompress()?;
        let mut transcript = Self::prepare_transcript(
            self.version,
            &self.owner,
            self.fee,
            self.nonce,
            &self.new_source_commitment,
        );

        // 0. Verify Signature
        // TODO

        // 1. Verify CommitmentEqProof
        let source_current_ciphertext = source_current_ciphertext.decompress()?;
        let new_ct = self.get_sender_new_balance_ct(&source_current_ciphertext)?;
        let new_source_commitment = self.new_source_commitment.decompress()?;

        println!(
            "verify {:?}",
            (
                &owner.compress(),
                &new_ct.compress(),
                &new_source_commitment.compress(),
            )
        );

        self.new_commitment_eq_proof.verify(
            &owner,
            &new_ct,
            &new_source_commitment,
            &mut transcript,
        )?;

        // 2. Verify every CtValidityProof
        if let TransactionType::Transfer(transfers) = &self.data {
            for transfer in transfers {
                let amount_commitment = transfer.amount_commitment.decompress()?;
                let amount_receiver_handle = transfer.amount_receiver_handle.decompress()?;

                transcript.transfer_proof_domain_separator();
                transcript.append_pubkey(b"dest_pubkey", &transfer.dest_pubkey);
                transcript.append_commitment(b"amount_commitment", &transfer.amount_commitment);
                transcript.append_handle(b"amount_sender_handle", &transfer.amount_sender_handle);
                transcript
                    .append_handle(b"amount_receiver_handle", &transfer.amount_receiver_handle);

                let receiver = transfer.dest_pubkey.decompress()?;

                transfer.ct_validity_proof.verify(
                    &amount_commitment,
                    &receiver,
                    &amount_receiver_handle,
                    &mut transcript,
                )?;
            }
        }

        // 3. Verify the aggregated RangeProof
        let value_commitments: Vec<_> = if let TransactionType::Transfer(transfers) = &self.data {
            iter::once(self.new_source_commitment.as_point())
                .chain(
                    transfers
                        .iter()
                        .map(|transfer| transfer.amount_commitment.as_point()),
                )
                .collect()
        } else {
            vec![self.new_source_commitment.as_point()]
        };

        // range proof will be verified in batch by caller

        Ok((transcript, value_commitments, new_ct.compress()))
    }

    pub fn verify_batch<B: BlockchainVerificationState>(
        state: &mut B,
        txs: &[Transaction],
    ) -> Result<(), VerificationError<B::Error>> {
        let mut prepared = txs
            .iter()
            .map(|tx| {
                let current_ciphertext = state
                    .get_account_balance(&tx.owner)
                    .map_err(VerificationError::State)?;

                let (transcript, commitments, new_ciphertext) =
                    tx.pre_verify(&current_ciphertext)?;

                state
                    .update_account_balance(&tx.owner, new_ciphertext)
                    .map_err(VerificationError::State)?;
                Ok((transcript, commitments))
            })
            .collect::<Result<Vec<_>, VerificationError<B::Error>>>()?;

        RangeProof::verify_batch(
            txs.iter()
                .zip(&mut prepared)
                .map(|(tx, (transcript, commitments))| {
                    tx.range_proof
                        .verification_view(transcript, commitments, 64)
                }),
            &BP_GENS,
            &PC_GENS,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }
}
