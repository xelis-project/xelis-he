use thiserror::Error;

#[macro_use]
pub(crate) mod macros;

mod compressed;
mod elgamal;
pub(crate) mod proofs;
mod transcript;
mod tx;

pub use compressed::{DecompressionError, ElGamalCiphertext, ElGamalPubkey};
pub use transcript::TranscriptError;
pub use elgamal::{
    ECDLPInstance, ElGamalKeypair as Keypair, ElGamalPubkey as Pubkey,
    ElGamalSecretKey as SecretKey,
};
pub use tx::{Transaction, TransactionType, Transfer};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum TransferProofGenerationError {
    #[error("not enough funds in the account")]
    InsufficientFunds,
    #[error("range proof generation failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum TransferProofVerificationError {
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
    pub new_source_balance: compressed::ElGamalCiphertext,
    pub new_dest_balance: compressed::ElGamalCiphertext,
}

impl Transfer {
    // sample usage
    pub fn apply_balances(
        &self,
        source_balance: &compressed::ElGamalCiphertext,
        dest_balance: &compressed::ElGamalCiphertext,
    ) -> ApplyBalancesResult {
        let source_ct = self.get_ciphertext(Role::Sender);
        let dest_ct = self.get_ciphertext(Role::Receiver);
        let source_bal = source_balance.decompress().unwrap();
        let dest_bal = dest_balance.decompress().unwrap();

        let new_source_balance = (&source_bal - &source_ct).compress();
        let new_dest_balance = (&dest_bal + &dest_ct).compress();
        ApplyBalancesResult {
            new_source_balance,
            new_dest_balance,
        }
    }

    pub fn get_ciphertext(&self, role: Role) -> ElGamalCiphertext {
        let handle = match role {
            Role::Receiver => self.amount_receiver_handle,
            Role::Sender => self.amount_sender_handle,
        };

        ElGamalCiphertext::new(
            self.amount_commitment.decompress().unwrap(),
            handle.decompress().unwrap(),
        )
    }

    /// Note: this function returns an `ECDLPInstance` object, which you will need to decode.
    pub fn decrypt_amount(&self, sk: &SecretKey, role: Role) -> ECDLPInstance {
        sk.decrypt(&self.get_ciphertext(role))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Account {
        keypair: elgamal::ElGamalKeypair,
        balance: u64,
        balance_ct: compressed::ElGamalCiphertext,
    }

    impl Account {
        fn new(balance: u64) -> Account {
            let keypair = elgamal::ElGamalKeypair::keygen();

            Account {
                balance,
                balance_ct: keypair.pubkey().encrypt(balance).compress(),
                keypair,
            }
        }

        fn create_transfer(
            &self,
            other: &Account,
            amount: u64,
        ) -> Result<Transfer, TransferProofGenerationError> {
            Transfer::new(
                &self.balance_ct,
                self.balance,
                amount,
                &self.keypair,
                &other.keypair.pubkey().compress(),
            )
        }
    }

    #[test]
    fn test_1() {
        let bob = Account::new(100);
        let alice = Account::new(0);

        let transfer = bob.create_transfer(&alice, 5).expect("generate");

        transfer
            .verify(
                &bob.keypair.pubkey().compress(),
                &bob.balance_ct,
                &alice.keypair.pubkey().compress(),
            )
            .expect("verify");
    }
}
