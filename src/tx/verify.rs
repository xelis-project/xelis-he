use bulletproofs::RangeProof;
use curve25519_dalek::{ristretto::CompressedRistretto, traits::Identity, RistrettoPoint, Scalar};
use merlin::Transcript;
use std::iter;
use thiserror::Error;

use crate::{
    compressed::DecompressionError,
    elgamal::{DecryptHandle, ElGamalCiphertext, PedersenCommitment},
    proofs::{BatchCollector, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    CompressedCiphertext, CompressedPubkey, Hash, ProofVerificationError, Role, SmartContractCall,
    Transaction, TransactionType, Transfer,
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

struct DecompressedTransferCt {
    amount_commitment: PedersenCommitment,
    amount_sender_handle: DecryptHandle,
    amount_receiver_handle: DecryptHandle,
}

impl DecompressedTransferCt {
    fn decompress(transfer: &Transfer) -> Result<Self, DecompressionError> {
        Ok(Self {
            amount_commitment: transfer.amount_commitment.decompress()?,
            amount_sender_handle: transfer.amount_sender_handle.decompress()?,
            amount_receiver_handle: transfer.amount_receiver_handle.decompress()?,
        })
    }

    fn get_ciphertext(&self, role: Role) -> ElGamalCiphertext {
        let handle = match role {
            Role::Receiver => self.amount_receiver_handle.clone(),
            Role::Sender => self.amount_sender_handle.clone(),
        };

        ElGamalCiphertext::new(self.amount_commitment.clone(), handle)
    }
}

impl Transaction {
    // get the new sender balance ciphertext
    fn get_sender_new_balance_ct(
        &self,
        source_current_balance: &ElGamalCiphertext,
        asset: &Hash,
        decompressed_transfers: &[DecompressedTransferCt],
    ) -> Result<ElGamalCiphertext, DecompressionError> {
        let mut bal = source_current_balance.clone();

        if asset.is_zeros() {
            // Fees are applied to the native blockchain asset only.
            bal -= Scalar::from(self.fee);
        }

        match &self.data {
            TransactionType::Transfer(transfers) => {
                for (transfer, d) in transfers.iter().zip(decompressed_transfers.iter()) {
                    if asset == &transfer.asset {
                        bal -= d.get_ciphertext(Role::Sender);
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

    pub(crate) fn prepare_transcript(
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
        sigma_batch_collector: &mut BatchCollector,
    ) -> Result<(Transcript, Vec<(RistrettoPoint, CompressedRistretto)>), VerificationError<B::Error>>
    {
        if !self.verify_commitment_assets() {
            return Err(VerificationError::Proof(ProofVerificationError::Format));
        }

        let transfers_decompressed = if let TransactionType::Transfer(transfers) = &self.data {
            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .collect::<Result<_, DecompressionError>>()
                .map_err(ProofVerificationError::from)?
        } else {
            vec![]
        };

        let new_source_commitments_decompressed = self
            .new_source_commitments
            .iter()
            .map(|commitment| commitment.new_source_commitment.decompress())
            .collect::<Result<Vec<_>, DecompressionError>>()
            .map_err(ProofVerificationError::from)?;

        let owner = self
            .source
            .decompress()
            .map_err(|err| VerificationError::Proof(err.into()))?;
        let mut transcript =
            Self::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        // 0. Verify Signature
        // TODO

        // 1. Verify CommitmentEqProofs

        for (commitment, new_source_commitment) in self
            .new_source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
        {
            let source_current_ciphertext = state
                .get_account_balance(&self.source, &commitment.asset)
                .map_err(VerificationError::State)?;

            let source_current_ciphertext = source_current_ciphertext
                .decompress()
                .map_err(|err| VerificationError::Proof(err.into()))?;
            let new_ct = self
                .get_sender_new_balance_ct(
                    &source_current_ciphertext,
                    &commitment.asset,
                    &transfers_decompressed,
                )
                .map_err(|err| VerificationError::Proof(err.into()))?;

            transcript.new_commitment_eq_proof_domain_separator();
            transcript.append_hash(b"new_source_commitment_asset", &commitment.asset);
            transcript
                .append_commitment(b"new_source_commitment", &commitment.new_source_commitment);

            commitment.new_commitment_eq_proof.pre_verify(
                &owner,
                &new_ct,
                &new_source_commitment,
                &mut transcript,
                sigma_batch_collector,
            )?;

            // Update source balance
            state
                .update_account_balance(&self.source, &commitment.asset, new_ct.compress())
                .map_err(VerificationError::State)?;
        }

        // 2. Verify every CtValidityProof
        if let TransactionType::Transfer(transfers) = &self.data {
            for (transfer, decompressed) in transfers.iter().zip(&transfers_decompressed) {
                let receiver = transfer
                    .dest_pubkey
                    .decompress()
                    .map_err(ProofVerificationError::from)?;

                // Update receiver balance

                let current_balance = state
                    .get_account_balance(&transfer.dest_pubkey, &transfer.asset)
                    .map_err(VerificationError::State)?
                    .decompress()
                    .map_err(ProofVerificationError::from)?;

                let receiver_ct = decompressed.get_ciphertext(Role::Receiver);
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

                transfer.ct_validity_proof.pre_verify(
                    &decompressed.amount_commitment,
                    &receiver,
                    &decompressed.amount_receiver_handle,
                    &mut transcript,
                    sigma_batch_collector,
                )?;
            }
        }

        // Prepare the new source commitments

        let new_source_commitments = self
            .new_source_commitments
            .iter()
            .zip(&new_source_commitments_decompressed)
            .map(|(commitment, new_source_commitment)| {
                (
                    new_source_commitment.as_point().clone(),
                    commitment.new_source_commitment.as_point(),
                )
            });

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
                .chain(transfers.iter().zip(&transfers_decompressed).map(
                    |(transfer, decompressed)| {
                        (
                            decompressed.amount_commitment.as_point().clone(),
                            transfer.amount_commitment.as_point(),
                        )
                    },
                ))
                .chain(
                    iter::repeat((RistrettoPoint::identity(), CompressedRistretto::identity()))
                        .take(n_dud_commitments),
                )
                .collect()
        } else {
            new_source_commitments
                .chain(
                    iter::repeat((RistrettoPoint::identity(), CompressedRistretto::identity()))
                        .take(n_dud_commitments),
                )
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
        let mut sigma_batch_collector = BatchCollector::default();
        let mut prepared = txs
            .iter()
            .map(|tx| {
                let (transcript, commitments) = tx.pre_verify(state, &mut sigma_batch_collector)?;
                Ok((transcript, commitments))
            })
            .collect::<Result<Vec<_>, VerificationError<B::Error>>>()?;

        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

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
        let mut sigma_batch_collector = BatchCollector::default();
        let (mut transcript, commitments) = self.pre_verify(state, &mut sigma_batch_collector)?;

        sigma_batch_collector
            .verify()
            .map_err(|_| ProofVerificationError::GenericProof)?;

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
        let transfers_decompressed = if let TransactionType::Transfer(transfers) = &self.data {
            transfers
                .iter()
                .map(DecompressedTransferCt::decompress)
                .map(Result::unwrap)
                .collect()
        } else {
            vec![]
        };

        for commitment in &self.new_source_commitments {
            let asset = &commitment.asset;
            let current_bal_sender = state
                .get_account_balance(&self.source, asset)?
                .decompress()
                .expect("ill-formed ciphertext");

            let new_ct = self
                .get_sender_new_balance_ct(&current_bal_sender, &asset, &transfers_decompressed)
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
