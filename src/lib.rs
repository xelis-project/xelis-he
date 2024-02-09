use thiserror::Error;

#[macro_use]
pub(crate) mod macros;

mod compressed;
mod elgamal;
pub(crate) mod proofs;
mod transcript;
mod tx;

pub use compressed::{CompressedCiphertext, CompressedPubkey, DecompressionError};
pub use elgamal::{ECDLPInstance, ElGamalKeypair, ElGamalPubkey, ElGamalSecretKey};
pub use transcript::TranscriptError;
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
    #[error("invalid format: {0}")]
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use self::tx::{
        builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
        BlockchainVerificationState,
    };

    use super::*;

    #[derive(Debug)]
    struct Ledger {
        accounts: HashMap<CompressedPubkey, Account>,
    }

    impl BlockchainVerificationState for Ledger {
        type Error = ();

        fn get_account_balance(
            &self,
            account: &CompressedPubkey,
        ) -> Result<CompressedCiphertext, Self::Error> {
            Ok(self.accounts[account].balance_ct)
        }

        fn update_account_balance(
            &mut self,
            account: &CompressedPubkey,
            new_ct: CompressedCiphertext,
        ) -> Result<(), Self::Error> {
            self.accounts.get_mut(account).unwrap().balance_ct = new_ct;
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    struct Account {
        keypair: ElGamalKeypair,
        balance_ct: CompressedCiphertext,
    }

    impl Account {
        fn new(balance: u64) -> Account {
            let keypair = ElGamalKeypair::keygen();

            Account {
                balance_ct: keypair.pubkey().encrypt(balance).compress(),
                keypair,
            }
        }
    }

    #[test]
    fn test_1() {
        let bob = Account::new(100);
        let alice = Account::new(0);
        let eve = Account::new(52);

        let mut ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
                (eve.keypair.pubkey().compress(), eve.clone()),
            ]
            .into(),
        };
        println!("{:?}", ledger);

        let bob = &ledger.accounts[&bob.keypair.pubkey().compress()];
        let alice = &ledger.accounts[&alice.keypair.pubkey().compress()];
        let eve = &ledger.accounts[&eve.keypair.pubkey().compress()];

        let (tx1, _, _) = TransactionBuilder {
            version: 1,
            owner: bob.keypair.pubkey().compress(),
            data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                dest_pubkey: alice.keypair.pubkey().compress(),
                amount: 52,
            }]),
            fee: 1,
            nonce: 1,
        }
        .build(&bob.keypair, 100, &bob.balance_ct)
        .unwrap();

        Transaction::verify_batch(&mut ledger, &vec![tx1]).unwrap();

        // assert_eq!()
    }
}
