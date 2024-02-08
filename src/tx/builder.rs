//! This file represents the transactions without the proofs
//! Not really a 'builder' per say
//! Intended to be used when creating a transaction before making the associated proofs and signature

use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use std::iter;

use crate::{
    elgamal::{PedersenCommitment, PedersenOpening},
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    CompressedCiphertext, CompressedPubkey, ElGamalKeypair, ProofGenerationError, Transaction,
    TransactionType, Transfer,
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
    pub to: CompressedPubkey,
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
    fn build(
        self,
        source_keypair: &ElGamalKeypair,
        source_current_balance: u64,
        source_current_ciphertext: &CompressedCiphertext,
    ) -> Result<(Transaction, CompressedCiphertext, u64), ProofGenerationError> {
        let cost = self.get_transaction_cost();
        let source_new_balance = source_current_balance
            .checked_sub(cost)
            .ok_or(ProofGenerationError::InsufficientFunds)?;

        let source_current_ciphertext = source_current_ciphertext.decompress()?;

        let new_source_ciphertext = source_current_ciphertext - Scalar::from(cost);

        // make a new comitment for the remaining balance in source
        let (new_source_commitment, source_opening) = PedersenCommitment::new(source_new_balance);
        let new_source_commitment_pod = new_source_commitment.compress();

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

        // next step consumes the amounts, so prepare the commitments for range proof beforehand
        let (commitments, openings) =
            if let TransactionTypeBuilder::Transfer(transfers) = &self.data {
                iter::once((source_new_balance, source_opening.as_scalar()))
                    .chain(transfers.iter().map(|transfer| {
                        (transfer.amount, PedersenOpening::generate_new().as_scalar())
                    }))
                    .unzip()
            } else {
                (vec![source_new_balance], vec![source_opening.as_scalar()])
            };

        // 2. Create the CtValaidityProofs
        let data = match self.data {
            TransactionTypeBuilder::Transfer(transfers) => TransactionType::Transfer(
                transfers
                    .into_iter()
                    .zip(openings.iter().skip(1))
                    .map(|(transfer, amount_opening)| {
                        let dest_pubkey = transfer.to.decompress()?;

                        let amount_opening = PedersenOpening::from_scalar(*amount_opening);
                        let amount_commitment =
                            PedersenCommitment::new_with_opening(transfer.amount, &amount_opening);
                        let amount_sender_handle =
                            source_keypair.pubkey().decrypt_handle(&amount_opening);
                        let amount_receiver_handle = dest_pubkey.decrypt_handle(&amount_opening);

                        let ct_validity_proof = CiphertextValidityProof::new(
                            &dest_pubkey,
                            transfer.amount,
                            &amount_opening,
                            &mut transcript,
                        );

                        Ok(Transfer {
                            to: transfer.to,
                            amount_commitment: amount_commitment.compress(),
                            amount_sender_handle: amount_sender_handle.compress(),
                            amount_receiver_handle: amount_receiver_handle.compress(),
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
