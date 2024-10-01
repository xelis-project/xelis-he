use bulletproofs::RangeProof;
use std::collections::HashMap;

pub mod builder;
mod verify;

pub use verify::BlockchainVerificationState;

use crate::{
    extra_data::{ExtraData, PlaintextData},
    compressed::{CompressedCommitment, CompressedHandle, DecompressionError},
    proofs::{CiphertextValidityProof, CommitmentEqProof},
    CompressedCiphertext, CompressedPubkey, ECDLPInstance, ElGamalSecretKey,
    ExtraDataDecryptionError, Hash, Role, Signature,
};

pub type MultiSig = Vec<(u8, Signature)>;

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transfer {
    pub asset: Hash,
    pub dest_pubkey: CompressedPubkey,
    // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    pub extra_data: Option<ExtraData>,

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

    /// This moves out the `extra_data`.
    pub fn decrypt_extra_data_in_place(
        &mut self,
        sk: &ElGamalSecretKey,
        role: Role,
    ) -> Result<Option<PlaintextData>, ExtraDataDecryptionError> {
        self.extra_data.take().map(|data| {
            Ok(data.decrypt_in_place(&sk, role)?)
        }).transpose()
    }

    pub fn decrypt_extra_data(
        &self,
        sk: &ElGamalSecretKey,
        role: Role,
    ) -> Result<Option<PlaintextData>, ExtraDataDecryptionError> {
        self.extra_data.clone().map(|data| {
            Ok(data.decrypt_in_place(&sk, role)?)
        }).transpose()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct SmartContractCall {
    pub contract: Hash,
    pub assets: HashMap<Hash, u64>,
    // TODO
    pub params: HashMap<String, String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TransactionType {
    Transfers(Vec<Transfer>),
    Burn { asset: Hash, amount: u64 },
    CallContract(SmartContractCall),
    // represent the code to deploy
    DeployContract(String),
    Multisig { signers: Vec<CompressedPubkey>, threshold: u8 },
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub(crate) struct NewSourceCommitment {
    pub(crate) new_source_commitment: CompressedCommitment,
    pub(crate) new_commitment_eq_proof: CommitmentEqProof,
    pub(crate) asset: Hash,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transaction {
    pub(crate) version: u8,
    pub(crate) source: CompressedPubkey,
    pub(crate) data: TransactionType,
    pub(crate) fee: u64,
    pub(crate) nonce: u64,
    /// We have one source_commitment and equality proof per asset used in the tx.
    pub(crate) new_source_commitments: Vec<NewSourceCommitment>,
    /// The range proof is aggregated across all transfers and across all assets.
    pub(crate) range_proof: RangeProof,
    /// Multisig signatures.
    /// Useful for directly accepted multisig transactions without any on-chain interaction.
    /// The first element of the tuple is the index of the signer
    pub(crate) multisig: Option<MultiSig>,
    /// Signature of the TX by the source.
    pub(crate) signature: Signature,
}

impl Transaction {
    pub fn get_version(&self) -> u8 {
        self.version
    }

    pub fn get_source(&self) -> &CompressedPubkey {
        &self.source
    }

    pub fn get_data(&self) -> &TransactionType {
        &self.data
    }

    pub fn get_fee(&self) -> u64 {
        self.fee
    }

    pub fn get_nonce(&self) -> u64 {
        self.nonce
    }

    pub fn get_multisisg(&self) -> Option<&Vec<(u8, Signature)>> {
        self.multisig.as_ref()
    }

    pub fn consume(self) -> (CompressedPubkey, TransactionType) {
        (self.source, self.data)
    }
}
