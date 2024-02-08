use bulletproofs::{ProofError, RangeProof};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use merlin::Transcript;
use std::iter;
use thiserror::Error;

use crate::{
    compressed::{self, DecompressionError},
    elgamal::ElGamalCiphertext,
    proofs::{CiphertextValidityProof, CommitmentEqProof, BP_GENS, PC_GENS},
    transcript::ProtocolTranscript,
    Role, TransferProofVerificationError,
};

#[derive(Error)]
pub enum VerificationError<T> {
    State(T),
    Proof(#[from] TransferProofVerificationError),
}

/// This trait is used by the batch verification function. It is intended to represent a virtual snapshot of the current blockchain
/// state, where the transactions can get applied in order.
pub trait BlockchainVerificationState {
    type Error;

    /// Get the balance ciphertext from an account
    fn get_account_balance(
        &self,
        account: &compressed::ElGamalPubkey,
    ) -> Result<compressed::ElGamalCiphertext, Self::Error>;

    /// Apply a new balance ciphertext to an account
    fn update_account_balance(
        &mut self,
        account: &compressed::ElGamalPubkey,
        new_ct: compressed::ElGamalCiphertext,
    ) -> Result<(), Self::Error>;
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Transfer {
    // pub asset: Hash,
    pub to: compressed::ElGamalPubkey,
    // pub extra_data: Option<Vec<u8>>, // we can put whatever we want up to EXTRA_DATA_LIMIT_SIZE bytes
    pub(crate) amount_commitment: compressed::PedersenCommitment,
    pub(crate) amount_sender_handle: compressed::DecryptHandle,
    pub(crate) amount_receiver_handle: compressed::DecryptHandle,
    ct_validity_proof: CiphertextValidityProof,
}

impl Transfer {
    pub fn get_ciphertext(&self, role: Role) -> compressed::ElGamalCiphertext {
        let handle = match role {
            Role::Receiver => self.amount_receiver_handle,
            Role::Sender => self.amount_sender_handle,
        };

        compressed::ElGamalCiphertext::new(self.amount_commitment, handle)
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
    owner: compressed::ElGamalPubkey,
    data: TransactionType,
    fee: u64,
    nonce: u64,
    // signature: Signature,
    range_proof: RangeProof,
    new_source_commitment: compressed::PedersenCommitment,
    new_commitment_eq_proof: CommitmentEqProof,
}

impl Transaction {
    // get the new sender balance ciphertext
    fn get_sender_new_balance_ct(
        &self,
        source_current_balance: &ElGamalCiphertext,
    ) -> Result<ElGamalCiphertext, DecompressionError> {
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

    fn prepare_transcript(&self) -> Transcript {
        let mut transcript = Transcript::new(b"transaction-proof");
        transcript.append_u64(b"version", self.version.into());
        transcript.append_pubkey(b"owner", &self.owner);
        transcript.append_u64(b"fee", self.fee);
        transcript.append_u64(b"nonce", self.nonce);
        transcript.append_commitment(b"new_source_commitment", &self.new_source_commitment);
        transcript
    }

    // internal, does not verify the range proof
    fn pre_verify(
        &self,
        source_current_ciphertext: &compressed::ElGamalCiphertext,
    ) -> Result<
        (
            Transcript,
            Vec<CompressedRistretto>,
            compressed::ElGamalCiphertext,
        ),
        TransferProofVerificationError,
    > {
        let owner = self.owner.decompress()?;
        let mut transcript = self.prepare_transcript();

        // 0. Verify Signature
        // TODO

        // 1. Verify CommitmentEqProof
        let source_current_ciphertext = source_current_ciphertext.decompress()?;
        let new_ct = self.get_sender_new_balance_ct(&source_current_ciphertext)?;
        let new_source_commitment = self.new_source_commitment.decompress()?;

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

                let receiver = transfer.to.decompress()?;

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
        mut state: B,
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
        .map_err(TransferProofVerificationError::from)?;

        Ok(())
    }
}
