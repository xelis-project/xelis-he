use bulletproofs::RangeProof;
use std::collections::HashMap;

pub mod builder;
mod verify;

pub use verify::{BlockchainVerificationState, VerificationError};

use crate::{
    compressed::{CompressedCommitment, CompressedHandle, DecompressionError},
    proofs::{CiphertextValidityProof, CommitmentEqProof},
    CompressedCiphertext, CompressedPubkey, ECDLPInstance, ElGamalSecretKey, Hash, Role,
};

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
