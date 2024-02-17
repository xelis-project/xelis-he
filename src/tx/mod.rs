use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, Scalar};
use merlin::Transcript;
use std::{collections::HashMap, iter};
use thiserror::Error;

pub mod builder;

use crate::{
    compressed::{CompressedCommitment, CompressedHandle, DecompressionError},
    elgamal::ElGamalCiphertext,
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    CompressedCiphertext, CompressedPubkey, ECDLPInstance, ElGamalSecretKey, Hash,
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
        asset: &Hash,
    ) -> Result<CompressedCiphertext, Self::Error>;

    /// Apply a new balance ciphertext to an account
    fn update_account_balance(
        &mut self,
        account: &CompressedPubkey,
        asset: &Hash,
        new_ct: CompressedCiphertext,
    ) -> Result<(), Self::Error>;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transfer {
    pub asset: Hash,
    pub dest_pubkey: CompressedPubkey,
    pub extra_data: Option<Vec<u8>>, // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes

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
    pub contract: Hash,
    pub assets: HashMap<Hash, u64>,
    pub params: HashMap<String, String>, // TODO
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum TransactionType {
    #[serde(rename = "transfers")]
    Transfer(Vec<Transfer>),
    #[serde(rename = "burn")]
    Burn { asset: Hash, amount: u64 },
    #[serde(rename = "call_contract")]
    CallContract(SmartContractCall),
    #[serde(rename = "deploy_contract")]
    DeployContract(String), // represent the code to deploy
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
struct NewSourceCommitment {
    new_source_commitment: CompressedCommitment,
    new_commitment_eq_proof: CommitmentEqProof,
    asset: Hash,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transaction {
    version: u8,
    source: CompressedPubkey,
    data: TransactionType,
    fee: u64,
    nonce: u64,
    // signature: Signature,
    /// We have one source_commitment and equality proof per asset used in the tx.
    new_source_commitments: Vec<NewSourceCommitment>,
    /// The range proof is aggregated across all transfers and across all assets.
    range_proof: RangeProof,
}

impl Transaction {
    // get the new sender balance ciphertext
    fn get_sender_new_balance_ct(
        &self,
        source_current_balance: &ElGamalCiphertext,
        asset: &Hash,
    ) -> Result<ElGamalCiphertext, DecompressionError> {
        let mut bal = source_current_balance.clone();

        if asset.is_zeros() {
            // Fees are applied to the native blockchain asset only.
            bal -= Scalar::from(self.fee);
        }

        match &self.data {
            TransactionType::Transfer(transfers) => {
                for transfer in transfers {
                    if asset == &transfer.asset {
                        bal -= transfer.get_ciphertext(Role::Sender).decompress()?;
                    }
                }
            }
            TransactionType::Burn {
                amount,
                asset: basset,
            } => {
                if asset == basset {
                    bal -= Scalar::from(*amount)
                }
            }
            TransactionType::CallContract(SmartContractCall { assets, .. }) => {
                if let Some(amount) = assets.get(asset) {
                    bal -= Scalar::from(*amount)
                }
            }
            TransactionType::DeployContract(_) => todo!(),
        }

        Ok(bal)
    }

    fn prepare_transcript(
        version: u8,
        source_pubkey: &CompressedPubkey,
        fee: u64,
        nonce: u64,
    ) -> Transcript {
        let mut transcript = Transcript::new(b"transaction-proof");
        transcript.append_u64(b"version", version.into());
        transcript.append_pubkey(b"source_pubkey", source_pubkey);
        transcript.append_u64(b"fee", fee);
        transcript.append_u64(b"nonce", nonce);
        transcript
    }

    // Verify that the commitment assets match the assets used in the tx
    fn verify_commitment_assets(&self) -> bool {
        let has_commitment_for_asset = |asset| {
            self.new_source_commitments
                .iter()
                .any(|c| &c.asset == asset)
        };

        let native_asset = Hash::default();
        if !has_commitment_for_asset(&native_asset) {
            return false;
        }

        // Check for duplicates
        // Don't bother with hashsets or anything, number of transfers should be constrained
        if self
            .new_source_commitments
            .iter()
            .enumerate()
            .any(|(i, c)| {
                self.new_source_commitments
                    .iter()
                    .enumerate()
                    .any(|(i2, c2)| i != i2 && &c.asset == &c2.asset)
            })
        {
            return false;
        }

        match &self.data {
            TransactionType::Transfer(transfers) => transfers
                .iter()
                .all(|transfer| has_commitment_for_asset(&transfer.asset)),
            TransactionType::Burn { asset, .. } => has_commitment_for_asset(asset),
            TransactionType::CallContract(SmartContractCall { assets, .. }) => {
                assets.keys().all(|key| has_commitment_for_asset(key))
            }
            TransactionType::DeployContract(_) => todo!(),
        }
    }

    // internal, does not verify the range proof
    // returns (transcript, commitments for range proof)
    fn pre_verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
    ) -> Result<(Transcript, Vec<CompressedRistretto>), VerificationError<B::Error>> {
        if !self.verify_commitment_assets() {
            return Err(VerificationError::Proof(ProofVerificationError::Format));
        }

        let owner = self
            .source
            .decompress()
            .map_err(|err| VerificationError::Proof(err.into()))?;
        let mut transcript =
            Self::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        // 0. Verify Signature
        // TODO

        // 1. Verify CommitmentEqProofs

        for commitment in &self.new_source_commitments {
            let source_current_ciphertext = state
                .get_account_balance(&self.source, &commitment.asset)
                .map_err(VerificationError::State)?;

            let source_current_ciphertext = source_current_ciphertext
                .decompress()
                .map_err(|err| VerificationError::Proof(err.into()))?;
            let new_ct = self
                .get_sender_new_balance_ct(&source_current_ciphertext, &commitment.asset)
                .map_err(|err| VerificationError::Proof(err.into()))?;
            let new_source_commitment = commitment
                .new_source_commitment
                .decompress()
                .map_err(|err| VerificationError::Proof(err.into()))?;

            transcript.new_commitment_eq_proof_domain_separator();
            transcript.append_hash(b"new_source_commitment_asset", &commitment.asset);
            transcript
                .append_commitment(b"new_source_commitment", &commitment.new_source_commitment);

            commitment.new_commitment_eq_proof.verify(
                &owner,
                &new_ct,
                &new_source_commitment,
                &mut transcript,
            )?;

            // Update source balance
            state
                .update_account_balance(&self.source, &commitment.asset, new_ct.compress())
                .map_err(VerificationError::State)?;
        }

        // 2. Verify every CtValidityProof
        if let TransactionType::Transfer(transfers) = &self.data {
            for transfer in transfers {
                let amount_commitment = transfer
                    .amount_commitment
                    .decompress()
                    .map_err(|err| VerificationError::Proof(err.into()))?;
                let amount_receiver_handle = transfer
                    .amount_receiver_handle
                    .decompress()
                    .map_err(|err| VerificationError::Proof(err.into()))?;

                let receiver = transfer
                    .dest_pubkey
                    .decompress()
                    .map_err(|err| VerificationError::Proof(err.into()))?;

                // Update receiver balance

                let current_balance = state
                    .get_account_balance(&transfer.dest_pubkey, &transfer.asset)
                    .map_err(VerificationError::State)?
                    .decompress()
                    .map_err(|err| VerificationError::Proof(err.into()))?;

                let receiver_ct = ElGamalCiphertext::new(
                    amount_commitment.clone(),
                    amount_receiver_handle.clone(),
                );
                let receiver_new_balance = current_balance + receiver_ct;

                state
                    .update_account_balance(
                        &transfer.dest_pubkey,
                        &transfer.asset,
                        receiver_new_balance.compress(),
                    )
                    .map_err(VerificationError::State)?;

                // Validity proof

                transcript.transfer_proof_domain_separator();
                transcript.append_pubkey(b"dest_pubkey", &transfer.dest_pubkey);
                transcript.append_commitment(b"amount_commitment", &transfer.amount_commitment);
                transcript.append_handle(b"amount_sender_handle", &transfer.amount_sender_handle);
                transcript
                    .append_handle(b"amount_receiver_handle", &transfer.amount_receiver_handle);

                transfer.ct_validity_proof.verify(
                    &amount_commitment,
                    &receiver,
                    &amount_receiver_handle,
                    &mut transcript,
                )?;
            }
        }

        // Prepare the new source commitments

        let new_source_commitments = self
            .new_source_commitments
            .iter()
            .map(|commitment| commitment.new_source_commitment.as_point());

        let mut n_commitments = self.new_source_commitments.len();
        if let TransactionType::Transfer(transfers) = &self.data {
            n_commitments += transfers.len()
        }

        // Create fake commitments to make `m` (party size) of the bulletproof a power of two.
        let n_dud_commitments = n_commitments
            .checked_next_power_of_two()
            .ok_or(ProofVerificationError::Format)?
            - n_commitments;

        let value_commitments: Vec<_> = if let TransactionType::Transfer(transfers) = &self.data {
            new_source_commitments
                .chain(
                    transfers
                        .iter()
                        .map(|transfer| transfer.amount_commitment.as_point().clone()),
                )
                .chain(iter::repeat(CompressedRistretto::identity()).take(n_dud_commitments))
                .collect()
        } else {
            new_source_commitments
                .chain(iter::repeat(CompressedRistretto::identity()).take(n_dud_commitments))
                .collect()
        };

        // 3. Verify the aggregated RangeProof

        // range proof will be verified in batch by caller

        Ok((transcript, value_commitments))
    }

    pub fn verify_batch<B: BlockchainVerificationState>(
        txs: &[Transaction],
        state: &mut B,
    ) -> Result<(), VerificationError<B::Error>> {
        let mut prepared = txs
            .iter()
            .map(|tx| {
                let (transcript, commitments) = tx.pre_verify(state)?;
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

    /// Verify one transaction. Use `verify_batch` to verify a batch of transactions.
    pub fn verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
    ) -> Result<(), VerificationError<B::Error>> {
        let (mut transcript, commitments) = self.pre_verify(state)?;

        RangeProof::verify_multiple(
            &self.range_proof,
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &commitments,
            64,
        )
        .map_err(ProofVerificationError::from)?;

        Ok(())
    }

    /// Assume the tx is valid, apply it to `state`. May panic if a ciphertext is ill-formed.
    pub fn apply_without_verify<B: BlockchainVerificationState>(
        &self,
        state: &mut B,
    ) -> Result<(), B::Error> {
        for commitment in &self.new_source_commitments {
            let asset = &commitment.asset;
            let current_bal_sender = state
                .get_account_balance(&self.source, asset)?
                .decompress()
                .expect("ill-formed ciphertext");

            let new_ct = self
                .get_sender_new_balance_ct(&current_bal_sender, &asset)
                .expect("ill-formed ciphertext");

            state.update_account_balance(&self.source, asset, new_ct.compress())?;
        }

        if let TransactionType::Transfer(transfers) = &self.data {
            for transfer in transfers {
                let current_bal = state
                    .get_account_balance(&transfer.dest_pubkey, &transfer.asset)?
                    .decompress()
                    .expect("ill-formed ciphertext");

                let receiver_ct = transfer
                    .get_ciphertext(Role::Receiver)
                    .decompress()
                    .expect("ill-formed ciphertext");

                let receiver_new_balance = current_bal + receiver_ct;

                state.update_account_balance(
                    &transfer.dest_pubkey,
                    &transfer.asset,
                    receiver_new_balance.compress(),
                )?;
            }
        }

        Ok(())
    }
}
