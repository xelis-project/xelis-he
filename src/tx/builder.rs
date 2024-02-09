//! This file represents the transactions without the proofs
//! Not really a 'builder' per say
//! Intended to be used when creating a transaction before making the associated proofs and signature

use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use std::{iter, mem};

use crate::{
    elgamal::{DecryptHandle, ElGamalCiphertext, PedersenCommitment, PedersenOpening},
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    CompressedCiphertext, CompressedPubkey, DecompressionError, ElGamalKeypair, ElGamalPubkey,
    ProofGenerationError, Transaction, TransactionType, Transfer,
};

use super::SmartContractCall;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum TransactionTypeBuilder {
    #[serde(rename = "transfers")]
    Transfer(Vec<TransferBuilder>),
    #[serde(rename = "burn")]
    Burn { /* asset: Hash,  */ amount: u64, },
    #[serde(rename = "call_contract")]
    CallContract(SmartContractCallBuilder),
    #[serde(rename = "deploy_contract")]
    DeployContract(String), // represent the code to deploy
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SmartContractCallBuilder {
    // pub contract: Hash,
    pub amount: u64, // TODO: change to assets
                     // pub assets: HashMap<Hash, u64>,
                     // pub params: HashMap<String, String> // TODO
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    // pub asset: Hash,
    pub dest_pubkey: CompressedPubkey,
    pub amount: u64,
    // pub extra_data: Option<Vec<u8>>, // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransactionBuilder {
    pub version: u8,
    pub owner: CompressedPubkey,
    pub data: TransactionTypeBuilder,
    pub fee: u64,
    pub nonce: u64,
}

impl TransactionBuilder {
    /// Compute the full cost of the transaction
    pub fn get_transaction_cost(&self) -> u64 {
        let mut bal = self.fee;
        match &self.data {
            TransactionTypeBuilder::Transfer(transfers) => {
                for transfer in transfers {
                    bal += transfer.amount;
                }
            }
            TransactionTypeBuilder::Burn { amount, .. } => bal += amount,
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { amount }) => {
                bal += amount
            }
            TransactionTypeBuilder::DeployContract(_) => todo!(),
        }

        bal
    }

    /// Returns (transaction, new_source_balance_ciphertext, new_source_balance).
    pub fn build(
        mut self,
        source_keypair: &ElGamalKeypair,
        source_current_balance: u64,
        source_current_ciphertext: &CompressedCiphertext,
    ) -> Result<(Transaction, CompressedCiphertext, u64), ProofGenerationError> {
        let cost = self.get_transaction_cost();
        let source_new_balance = source_current_balance
            .checked_sub(cost)
            .ok_or(ProofGenerationError::InsufficientFunds)?;

        println!("cost {cost:?}");

        let source_current_ciphertext = source_current_ciphertext.decompress()?;

        // 0.a Create the commitments

        struct TransferWithCommitment {
            inner: TransferBuilder,
            amount_commitment: PedersenCommitment,
            amount_sender_handle: DecryptHandle,
            amount_receiver_handle: DecryptHandle,
            dest_pubkey: ElGamalPubkey,
            amount_opening: PedersenOpening,
        }

        let new_source_opening = PedersenOpening::generate_new();

        let (transfers, commitments, openings) =
            if let TransactionTypeBuilder::Transfer(transfers) = &mut self.data {
                let transfers = mem::take(transfers);
                let transfers = transfers
                    .into_iter()
                    .map(|transfer| {
                        let dest_pubkey = transfer.dest_pubkey.decompress()?;

                        let amount_opening = PedersenOpening::generate_new();
                        let amount_commitment =
                            PedersenCommitment::new_with_opening(transfer.amount, &amount_opening);
                        let amount_sender_handle =
                            source_keypair.pubkey().decrypt_handle(&amount_opening);
                        let amount_receiver_handle = dest_pubkey.decrypt_handle(&amount_opening);

                        Ok(TransferWithCommitment {
                            inner: transfer,
                            amount_commitment,
                            amount_sender_handle,
                            amount_receiver_handle,
                            dest_pubkey,
                            amount_opening,
                        })
                    })
                    .collect::<Result<Vec<_>, DecompressionError>>()?;

                let (commitments, openings) =
                    iter::once((source_new_balance, new_source_opening.as_scalar()))
                        .chain(transfers.iter().map(|transfer| {
                            (transfer.inner.amount, transfer.amount_opening.as_scalar())
                        }))
                        .unzip();

                (transfers, commitments, openings)
            } else {
                (
                    vec![],
                    vec![source_new_balance],
                    vec![new_source_opening.as_scalar()],
                )
            };

        // 0.b Make a new comitment for the remaining balance in source

        // 0.c Compute the new balance
        // We can't just do `source_current_ciphertext - Scalar::from(cost)`, as we need the pedersen openings to
        // match up with the transfer amounts.

        let (new_source_commitment, source_opening) = PedersenCommitment::new(source_new_balance);
        let new_source_commitment_pod = new_source_commitment.compress();

        let mut new_source_ciphertext = source_current_ciphertext - Scalar::from(self.fee);
        match &self.data {
            TransactionTypeBuilder::Transfer(_) => {
                for transfer in &transfers {
                    new_source_ciphertext -= ElGamalCiphertext::new(
                        transfer.amount_commitment.clone(),
                        transfer.amount_sender_handle.clone(),
                    );
                }
            }
            TransactionTypeBuilder::Burn { amount, .. } => {
                new_source_ciphertext -= Scalar::from(*amount)
            }
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { amount }) => {
                new_source_ciphertext -= Scalar::from(*amount)
            }
            TransactionTypeBuilder::DeployContract(_) => todo!(),
        }

        let mut transcript = Transaction::prepare_transcript(
            self.version,
            &self.owner,
            self.fee,
            self.nonce,
            &new_source_commitment_pod,
        );

        // 1. Make the CommitmentEqProof
        let new_commitment_eq_proof = CommitmentEqProof::new(
            &source_keypair,
            &new_source_ciphertext,
            &source_opening,
            source_new_balance,
            &mut transcript,
        );

        // 2. Create the CtValidityProofs
        let data = match self.data {
            TransactionTypeBuilder::Transfer(_) => TransactionType::Transfer(
                transfers
                    .into_iter()
                    .map(|transfer| {
                        let amount_commitment = transfer.amount_commitment.compress();

                        transcript.transfer_proof_domain_separator();
                        transcript.append_pubkey(b"dest_pubkey", &transfer.inner.dest_pubkey);
                        transcript.append_commitment(b"amount_commitment", &amount_commitment);

                        let ct_validity_proof = CiphertextValidityProof::new(
                            &transfer.dest_pubkey,
                            transfer.inner.amount,
                            &transfer.amount_opening,
                            &mut transcript,
                        );

                        Ok(Transfer {
                            dest_pubkey: transfer.inner.dest_pubkey,
                            amount_commitment,
                            amount_sender_handle: transfer.amount_sender_handle.compress(),
                            amount_receiver_handle: transfer.amount_receiver_handle.compress(),
                            ct_validity_proof,
                        })
                    })
                    .collect::<Result<_, ProofGenerationError>>()?,
            ),
            TransactionTypeBuilder::Burn { amount } => TransactionType::Burn { amount },
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { amount }) => {
                TransactionType::CallContract(SmartContractCall { amount })
            }
            TransactionTypeBuilder::DeployContract(c) => TransactionType::DeployContract(c),
        };

        // 3. Create the RangeProof

        let (range_proof, _commitments) = RangeProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &commitments,
            &openings,
            64,
        )?;

        Ok((
            Transaction {
                version: self.version,
                owner: self.owner,
                data,
                fee: self.fee,
                nonce: self.nonce,
                range_proof,
                new_source_commitment: new_source_commitment_pod,
                new_commitment_eq_proof,
            },
            new_source_ciphertext.compress(),
            source_new_balance,
        ))
    }
}
