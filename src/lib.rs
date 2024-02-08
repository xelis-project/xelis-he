use thiserror::Error;

#[macro_use]
pub(crate) mod macros;

mod compressed;
mod elgamal;
pub(crate) mod proofs;
mod transcript;
mod tx;

pub use compressed::{DecompressionError, CompressedCiphertext, CompressedPubkey};
pub use transcript::TranscriptError;
pub use elgamal::{
    ECDLPInstance, ElGamalKeypair, ElGamalPubkey,
    ElGamalSecretKey,
};
pub use tx::{Transaction, TransactionType, Transfer};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofGenerationError {
    #[error("invalid format")]
    Format(#[from] DecompressionError),
    #[error("not enough funds in the account")]
    InsufficientFunds,
    #[error("range proof generation failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationError {
    #[error("invalid format")]
    Format(#[from] DecompressionError),
    #[error("commitment equality proof verification failed")]
    CommitmentEqProof,
    #[error("ciphertext validity proof verification failed")]
    CiphertextValidityProof,
    #[error("range proof verification failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
    #[error("transcript error: {0}")]
    Transcript(#[from] TranscriptError),
}

#[derive(Clone, Copy)]
pub enum Role {
    Sender,
    Receiver,
}

pub struct ApplyBalancesResult {
    pub new_source_balance: CompressedCiphertext,
    pub new_dest_balance: CompressedCiphertext,
}

#[cfg(test)]
mod tests {
    use super::*;

    // struct Account {
    //     keypair: elgamal::ElGamalKeypair,
    //     balance: u64,
    //     balance_ct: CompressedCiphertext,
    // }

    // impl Account {
    //     fn new(balance: u64) -> Account {
    //         let keypair = elgamal::ElGamalKeypair::keygen();

    //         Account {
    //             balance,
    //             balance_ct: keypair.pubkey().encrypt(balance).compress(),
    //             keypair,
    //         }
    //     }

    //     fn create_transfer(
    //         &self,
    //         other: &Account,
    //         amount: u64,
    //     ) -> Result<Transfer, ProofGenerationError> {
    //         Transfer::new(
    //             &self.balance_ct,
    //             self.balance,
    //             amount,
    //             &self.keypair,
    //             &other.keypair.pubkey().compress(),
    //         )
    //     }
    // }

    // #[test]
    // fn test_1() {
    //     let bob = Account::new(100);
    //     let alice = Account::new(0);

    //     let transfer = bob.create_transfer(&alice, 5).expect("generate");

    //     transfer
    //         .verify(
    //             &bob.keypair.pubkey().compress(),
    //             &bob.balance_ct,
    //             &alice.keypair.pubkey().compress(),
    //         )
    //         .expect("verify");
    // }
}
