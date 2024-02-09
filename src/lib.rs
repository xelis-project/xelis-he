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
pub use tx::{builder, Transaction, TransactionType, Transfer};

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofGenerationError {
    #[error("invalid format")]
    Decompression(#[from] DecompressionError),
    #[error("not enough funds in the account")]
    InsufficientFunds,
    #[error("range proof generation failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
    #[error("invalid format")]
    Format,
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum ProofVerificationError {
    #[error("invalid format: {0}")]
    Decompression(#[from] DecompressionError),
    #[error("commitment equality proof verification failed")]
    CommitmentEqProof,
    #[error("ciphertext validity proof verification failed")]
    CiphertextValidityProof,
    #[error("range proof verification failed: {0}")]
    RangeProof(#[from] bulletproofs::ProofError),
    #[error("transcript error: {0}")]
    Transcript(#[from] TranscriptError),
    #[error("invalid format")]
    Format,
}

#[derive(Clone, Copy)]
pub enum Role {
    Sender,
    Receiver,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use curve25519_dalek::{RistrettoPoint, Scalar};

    use self::tx::{
        builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
        BlockchainVerificationState,
    };

    use super::*;

    #[derive(Debug, Clone)]
    struct Ledger {
        accounts: HashMap<CompressedPubkey, Account>,
    }

    impl Ledger {
        fn get_account(&self, account: &CompressedPubkey) -> &Account {
            &self.accounts[account]
        }
        fn get_bal_decrypted(&self, account: &CompressedPubkey) -> RistrettoPoint {
            let account = &self.accounts[account];
            *account
                .keypair
                .secret()
                .decrypt(&account.balance_ct.decompress().unwrap())
                .as_point()
        }
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
    fn realistic_test() {
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

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();
        let eve = eve.keypair.pubkey().compress();

        let (tx1, _, _) = {
            let builder = TransactionBuilder {
                version: 1,
                owner: bob,
                data: TransactionTypeBuilder::Transfer(vec![
                    TransferBuilder {
                        dest_pubkey: alice,
                        amount: 52,
                    },
                    TransferBuilder {
                        dest_pubkey: eve,
                        amount: 4,
                    },
                ]),
                fee: 1,
                nonce: 1,
            };
            assert_eq!(52 + 4 + 1, builder.get_transaction_cost());

            builder
                .build(
                    &ledger.get_account(&bob).keypair,
                    100,
                    &ledger.get_account_balance(&bob).unwrap(),
                )
                .unwrap()
        };

        let (tx2, _, _) = {
            let builder = TransactionBuilder {
                version: 1,
                owner: alice,
                data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                    dest_pubkey: eve,
                    amount: 30,
                }]),
                fee: 1,
                nonce: 1,
            };
            assert_eq!(30 + 1, builder.get_transaction_cost());

            // the second tx must be based on alice's ciphertext _after_ the first tx
            let mut ledger_after_tx1 = ledger.clone();
            tx1.apply_without_verify(&mut ledger_after_tx1).unwrap();

            builder
                .build(
                    &ledger_after_tx1.get_account(&alice).keypair,
                    0 + 52,
                    &ledger_after_tx1.get_account_balance(&alice).unwrap(),
                )
                .unwrap()
        };

        Transaction::verify_batch(&vec![tx1, tx2], &mut ledger).unwrap();

        assert_eq!(
            ledger.get_bal_decrypted(&bob),
            RistrettoPoint::mul_base(&Scalar::from(100u64 - 52 - 4 - 1))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice),
            RistrettoPoint::mul_base(&Scalar::from(0u64 + 52 - 30 - 1))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&eve),
            RistrettoPoint::mul_base(&Scalar::from(52u64 + 4 + 30))
        );
    }
}
