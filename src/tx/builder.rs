//! This file represents the transactions without the proofs
//! Not really a 'builder' per say
//! Intended to be used when creating a transaction before making the associated proofs and signature

use bulletproofs::RangeProof;
use curve25519_dalek::Scalar;
use std::{
    collections::{HashMap, HashSet},
    iter,
};
use thiserror::Error;

use crate::{
    aead::{derive_aead_key_from_opening, PlaintextData},
    elgamal::{DecryptHandle, ElGamalCiphertext, PedersenCommitment, PedersenOpening},
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    tx::NewSourceCommitment,
    CompressedCiphertext, CompressedPubkey, ElGamalKeypair, ElGamalPubkey, Hash,
    ProofGenerationError, Role, Transaction, TransactionType, Transfer,
};

use super::SmartContractCall;

#[derive(Error, Debug, Clone)]
pub enum GenerationError<T> {
    State(T),
    Proof(#[from] ProofGenerationError),
}

/// If the returned balance and ct do not match, the build function will panic and/or
/// the proof will be invalid.
pub trait GetBlockchainAccountBalance {
    type Error;

    /// Get the balance from the source
    fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error>;

    /// Get the balance ciphertext from the source
    fn get_account_ct(&self, asset: &Hash) -> Result<CompressedCiphertext, Self::Error>;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub enum TransactionTypeBuilder {
    #[serde(rename = "transfers")]
    Transfer(Vec<TransferBuilder>),
    #[serde(rename = "burn")]
    Burn { asset: Hash, amount: u64 },
    #[serde(rename = "call_contract")]
    CallContract(SmartContractCallBuilder),
    #[serde(rename = "deploy_contract")]
    DeployContract(String), // represent the code to deploy
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SmartContractCallBuilder {
    pub contract: Hash,
    pub assets: HashMap<Hash, u64>,
    pub params: HashMap<String, String>, // TODO
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransferBuilder {
    pub asset: Hash,
    pub amount: u64, // FIXME: should be zeroized
    pub dest_pubkey: CompressedPubkey,
    pub extra_data: Option<PlaintextData>, // TODO: size limits
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct TransactionBuilder {
    pub version: u8,
    pub source: CompressedPubkey,
    pub data: TransactionTypeBuilder,
    pub fee: u64,
    pub nonce: u64,
}

// Internal struct for build
struct TransferWithCommitment {
    inner: TransferBuilder,
    amount_commitment: PedersenCommitment,
    amount_sender_handle: DecryptHandle,
    amount_receiver_handle: DecryptHandle,
    dest_pubkey: ElGamalPubkey,
    amount_opening: PedersenOpening,
}

impl TransferWithCommitment {
    fn get_ciphertext(&self, role: Role) -> ElGamalCiphertext {
        let handle = match role {
            Role::Receiver => self.amount_receiver_handle.clone(),
            Role::Sender => self.amount_sender_handle.clone(),
        };

        ElGamalCiphertext::new(self.amount_commitment.clone(), handle)
    }
}

impl TransactionBuilder {
    fn get_new_source_ct(
        &self,
        mut ct: ElGamalCiphertext,
        asset: &Hash,
        transfers: &[TransferWithCommitment],
    ) -> ElGamalCiphertext {
        if asset.is_zeros() {
            // Fees are applied to the native blockchain asset only.
            ct -= Scalar::from(self.fee);
        }

        match &self.data {
            TransactionTypeBuilder::Transfer(_) => {
                for transfer in transfers {
                    if &transfer.inner.asset == asset {
                        ct -= transfer.get_ciphertext(Role::Sender);
                    }
                }
            }
            TransactionTypeBuilder::Burn {
                amount,
                asset: basset,
            } => {
                if asset == basset {
                    ct -= Scalar::from(*amount)
                }
            }
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { assets, .. }) => {
                if let Some(&amount) = assets.get(asset) {
                    ct -= Scalar::from(amount)
                }
            }
            TransactionTypeBuilder::DeployContract(_) => todo!(),
        }

        ct
    }

    /// Compute the full cost of the transaction
    pub fn get_transaction_cost(&self, asset: &Hash) -> u64 {
        let mut cost = 0;

        if asset.is_zeros() {
            // Fees are applied to the native blockchain asset only.
            cost += self.fee;
        }

        match &self.data {
            TransactionTypeBuilder::Transfer(transfers) => {
                for transfer in transfers {
                    if &transfer.asset == asset {
                        cost += transfer.amount;
                    }
                }
            }
            TransactionTypeBuilder::Burn {
                amount,
                asset: basset,
            } => {
                if basset == asset {
                    cost += amount
                }
            }
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { assets, .. }) => {
                if let Some(amount) = assets.get(asset) {
                    cost += amount
                }
            }
            TransactionTypeBuilder::DeployContract(_) => todo!(),
        }

        cost
    }

    pub fn used_assets(&self) -> HashSet<Hash> {
        let mut consumed = HashSet::new();

        // Native asset is always used. (fees)
        consumed.insert(Hash::default());

        match &self.data {
            TransactionTypeBuilder::Transfer(transfers) => {
                for transfer in transfers {
                    consumed.insert(transfer.asset.clone());
                }
            }
            TransactionTypeBuilder::Burn { asset, .. } => {
                consumed.insert(asset.clone());
            }
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder { assets, .. }) => {
                consumed.extend(assets.keys().cloned());
            }
            TransactionTypeBuilder::DeployContract(_) => todo!(),
        }

        consumed
    }

    pub fn build<B: GetBlockchainAccountBalance>(
        mut self,
        state: &mut B,
        source_keypair: &ElGamalKeypair,
    ) -> Result<Transaction, GenerationError<B::Error>> {
        // 0.a Create the commitments

        let used_assets = self.used_assets();

        let transfers = if let TransactionTypeBuilder::Transfer(transfers) = &mut self.data {
            transfers
                .iter()
                .map(|transfer| {
                    let dest_pubkey = transfer
                        .dest_pubkey
                        .decompress()
                        .map_err(|err| GenerationError::Proof(err.into()))?;

                    let amount_opening = PedersenOpening::generate_new();
                    let amount_commitment =
                        PedersenCommitment::new_with_opening(transfer.amount, &amount_opening);
                    let amount_sender_handle =
                        source_keypair.pubkey().decrypt_handle(&amount_opening);
                    let amount_receiver_handle = dest_pubkey.decrypt_handle(&amount_opening);

                    Ok(TransferWithCommitment {
                        inner: transfer.clone(),
                        amount_commitment,
                        amount_sender_handle,
                        amount_receiver_handle,
                        dest_pubkey,
                        amount_opening,
                    })
                })
                .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?
        } else {
            vec![]
        };

        let mut transcript =
            Transaction::prepare_transcript(self.version, &self.source, self.fee, self.nonce);

        let mut range_proof_openings: Vec<_> =
            iter::repeat_with(|| PedersenOpening::generate_new().as_scalar())
                .take(used_assets.len())
                .collect();

        let mut range_proof_values: Vec<_> = used_assets
            .iter()
            .map(|asset| {
                let cost = self.get_transaction_cost(&asset);
                let source_new_balance = state
                    .get_account_balance(asset)
                    .map_err(GenerationError::State)?
                    .checked_sub(cost)
                    .ok_or(ProofGenerationError::InsufficientFunds)?;

                Ok(source_new_balance)
            })
            .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?;

        let new_source_commitments = used_assets
            .into_iter()
            .zip(&range_proof_openings)
            .zip(&range_proof_values)
            .map(|((asset, new_source_opening), &source_new_balance)| {
                let new_source_opening = PedersenOpening::from_scalar(*new_source_opening);

                let source_current_ciphertext = state
                    .get_account_ct(&asset)
                    .map_err(GenerationError::State)?
                    .decompress()
                    .map_err(|err| GenerationError::Proof(err.into()))?;

                let new_source_commitment =
                    PedersenCommitment::new_with_opening(source_new_balance, &new_source_opening);
                let new_source_commitment = new_source_commitment.compress();

                let new_source_ciphertext =
                    self.get_new_source_ct(source_current_ciphertext, &asset, &transfers);

                // 1. Make the CommitmentEqProof

                transcript.new_commitment_eq_proof_domain_separator();
                transcript.append_hash(b"new_source_commitment_asset", &asset);
                transcript.append_commitment(b"new_source_commitment", &new_source_commitment);

                let new_commitment_eq_proof = CommitmentEqProof::new(
                    &source_keypair,
                    &new_source_ciphertext,
                    &new_source_opening,
                    source_new_balance,
                    &mut transcript,
                );

                Ok(NewSourceCommitment {
                    asset,
                    new_source_commitment,
                    new_commitment_eq_proof,
                })
            })
            .collect::<Result<Vec<_>, GenerationError<B::Error>>>()?;

        let transfers = if let TransactionTypeBuilder::Transfer(_) = &mut self.data {
            range_proof_values.reserve(transfers.len());
            range_proof_openings.reserve(transfers.len());

            let transfers = transfers
                .into_iter()
                .map(|transfer| {
                    let amount_commitment = transfer.amount_commitment.compress();
                    let amount_sender_handle = transfer.amount_sender_handle.compress();
                    let amount_receiver_handle = transfer.amount_receiver_handle.compress();

                    transcript.transfer_proof_domain_separator();
                    transcript.append_pubkey(b"dest_pubkey", &transfer.inner.dest_pubkey);
                    transcript.append_commitment(b"amount_commitment", &amount_commitment);
                    transcript.append_handle(b"amount_sender_handle", &amount_sender_handle);
                    transcript.append_handle(b"amount_receiver_handle", &amount_receiver_handle);

                    let ct_validity_proof = CiphertextValidityProof::new(
                        &transfer.dest_pubkey,
                        transfer.inner.amount,
                        &transfer.amount_opening,
                        &mut transcript,
                    );

                    range_proof_values.push(transfer.inner.amount);
                    range_proof_openings.push(transfer.amount_opening.as_scalar());

                    // encrypt extra data
                    let extra_data = transfer.inner.extra_data.map(|data| {
                        let k = derive_aead_key_from_opening(&transfer.amount_opening);
                        data.encrypt_in_place(&k)
                    });

                    Transfer {
                        amount_commitment,
                        amount_receiver_handle,
                        amount_sender_handle,
                        dest_pubkey: transfer.inner.dest_pubkey,
                        asset: transfer.inner.asset,
                        ct_validity_proof,
                        extra_data,
                    }
                })
                .collect::<Vec<_>>();

            transfers
        } else {
            vec![]
        };

        let n_commitments = range_proof_values.len();

        // Create fake commitments to make `m` (party size) of the bulletproof a power of two.
        let n_dud_commitments = n_commitments
            .checked_next_power_of_two()
            .ok_or(ProofGenerationError::Format)?
            - n_commitments;

        range_proof_values.extend(iter::repeat(0u64).take(n_dud_commitments));
        range_proof_openings.extend(iter::repeat(Scalar::ZERO).take(n_dud_commitments));

        let data = match self.data {
            TransactionTypeBuilder::Transfer(_) => TransactionType::Transfer(transfers),
            TransactionTypeBuilder::Burn { amount, asset } => {
                TransactionType::Burn { amount, asset }
            }
            TransactionTypeBuilder::CallContract(SmartContractCallBuilder {
                assets,
                contract,
                params,
            }) => TransactionType::CallContract(SmartContractCall {
                assets,
                contract,
                params,
            }),
            TransactionTypeBuilder::DeployContract(c) => TransactionType::DeployContract(c),
        };

        // 3. Create the RangeProof

        let (range_proof, _commitments) = RangeProof::prove_multiple(
            &BP_GENS,
            &PC_GENS,
            &mut transcript,
            &range_proof_values,
            &range_proof_openings,
            64,
        )
        .map_err(ProofGenerationError::from)?;

        Ok(Transaction {
            version: self.version,
            source: self.source,
            data,
            fee: self.fee,
            nonce: self.nonce,
            range_proof,
            new_source_commitments,
        })
    }
}
