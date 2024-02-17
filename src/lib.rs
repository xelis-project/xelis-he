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

// Replace with a real hash
#[derive(
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    std::hash::Hash,
    Default,
)]

pub struct Hash([u8; 32]);

impl Hash {
    pub fn is_zeros(&self) -> bool {
        self.0 == [0; 32]
    }
}

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

    use self::{builder::GetBlockchainAccountBalance, tx::{
        builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
        BlockchainVerificationState,
    }};

    use super::*;

    #[derive(Debug, Clone)]
    struct Ledger {
        accounts: HashMap<CompressedPubkey, Account>,
    }

    impl Ledger {
        fn get_account(&self, account: &CompressedPubkey) -> &Account {
            &self.accounts[account]
        }
        fn get_bal_decrypted(&self, account: &CompressedPubkey, asset: &Hash) -> RistrettoPoint {
            let account = &self.accounts[account];
            *account
                .keypair
                .secret()
                .decrypt(&account.balances[asset].decompress().unwrap())
                .as_point()
        }
    }

    impl BlockchainVerificationState for Ledger {
        type Error = ();

        fn get_account_balance(
            &self,
            account: &CompressedPubkey,
            asset: &Hash,
        ) -> Result<CompressedCiphertext, Self::Error> {
            Ok(self.accounts[account].balances[asset])
        }

        fn update_account_balance(
            &mut self,
            account: &CompressedPubkey,
            asset: &Hash,
            new_ct: CompressedCiphertext,
        ) -> Result<(), Self::Error> {
            *self.accounts
                .get_mut(account)
                .unwrap()
                .balances
                .get_mut(asset)
                .unwrap() = new_ct;
            Ok(())
        }
    }

    struct GenerationBalance {
        balances: HashMap<Hash, u64>,
        account: Account,
    }

    impl GetBlockchainAccountBalance for GenerationBalance {
        type Error = ();

        fn get_account_balance(&self, asset: &Hash) -> Result<u64, Self::Error> {
            Ok(self.balances[asset])
        }

        fn get_account_ct(&self, asset: &Hash) -> Result<CompressedCiphertext, Self::Error> {
            Ok(self.account.balances[asset])
        }
    }

    #[derive(Clone, Debug)]
    struct Account {
        keypair: ElGamalKeypair,
        balances: HashMap<Hash, CompressedCiphertext>,
    }

    impl Account {
        fn new(balances: impl IntoIterator<Item = (Hash, u64)>) -> Account {
            let keypair = ElGamalKeypair::keygen();

            Account {
                balances: balances
                    .into_iter()
                    .map(|(asset, balance)| (asset, keypair.pubkey().encrypt(balance).compress()))
                    .collect(),
                keypair,
            }
        }
    }

    #[test]
    fn realistic_test() {
        let bob = Account::new([(Hash([0; 32]), 100), (Hash([55; 32]), 2)]);
        let alice = Account::new([(Hash([0; 32]), 0), (Hash([55; 32]), 0)]);
        let eve = Account::new([(Hash([0; 32]), 52), (Hash([55; 32]), 0)]);

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

        let tx1 = {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfer(vec![
                    TransferBuilder {
                        dest_pubkey: alice,
                        amount: 52,
                        asset: Hash([0; 32]),
                        extra_data: Default::default(),
                    },
                    TransferBuilder {
                        dest_pubkey: eve,
                        amount: 4,
                        asset: Hash([0; 32]),
                        extra_data: Default::default(),
                    },
                    TransferBuilder {
                        dest_pubkey: eve,
                        amount: 2,
                        asset: Hash([55; 32]),
                        extra_data: Default::default(),
                    },
                ]),
                fee: 1,
                nonce: 1,
            };
            assert_eq!(52 + 4 + 1, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(2, builder.get_transaction_cost(&Hash([55; 32])));

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100), (Hash([55; 32]), 2)].into(),
                        account: ledger.get_account(&bob).clone(),
                    },
                    &ledger.get_account(&bob).keypair,
                )
                .unwrap()
        };

        let tx2 = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice,
                data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                    dest_pubkey: eve,
                    amount: 30,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 1,
                nonce: 1,
            };
            assert_eq!(30 + 1, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(0, builder.get_transaction_cost(&Hash([55; 32])));

            // the second tx must be based on alice's ciphertext _after_ the first tx
            let mut ledger_after_tx1 = ledger.clone();
            tx1.apply_without_verify(&mut ledger_after_tx1).unwrap();

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 0 + 52)].into(),
                        account: ledger_after_tx1.get_account(&alice).clone(),
                    },
                    &ledger_after_tx1.get_account(&alice).keypair,
                )
                .unwrap()
        };

        Transaction::verify_batch(&vec![tx1, tx2], &mut ledger).unwrap();

        assert_eq!(
            ledger.get_bal_decrypted(&bob, &Hash([0; 32])),
            RistrettoPoint::mul_base(&Scalar::from(100u64 - 52 - 4 - 1))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&bob, &Hash([55; 32])),
            RistrettoPoint::mul_base(&Scalar::from(2u64 - 2))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice, &Hash([0; 32])),
            RistrettoPoint::mul_base(&Scalar::from(0u64 + 52 - 30 - 1))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice, &Hash([55; 32])),
            RistrettoPoint::mul_base(&Scalar::from(0u64))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&eve, &Hash([0; 32])),
            RistrettoPoint::mul_base(&Scalar::from(52u64 + 4 + 30))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&eve, &Hash([55; 32])),
            RistrettoPoint::mul_base(&Scalar::from(0u64 + 2))
        );
    }

    #[test]
    fn non_native_asset() {
        let bob = Account::new([(Hash([0; 32]), 100), (Hash([55; 32]), 2)]);
        let alice = Account::new([(Hash([0; 32]), 0), (Hash([55; 32]), 0)]);

        let mut ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
            ]
            .into(),
        };

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfer(vec![
                    TransferBuilder {
                        dest_pubkey: alice,
                        amount: 2,
                        asset: Hash([55; 32]),
                        extra_data: Default::default(),
                    },
                ]),
                fee: 10,
                nonce: 1,
            };
            assert_eq!(10, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(2, builder.get_transaction_cost(&Hash([55; 32])));

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100), (Hash([55; 32]), 2)].into(),
                        account: ledger.get_account(&bob).clone(),
                    },
                    &ledger.get_account(&bob).keypair,
                )
                .unwrap()
        };

        Transaction::verify(&tx, &mut ledger).unwrap();

        assert_eq!(
            ledger.get_bal_decrypted(&bob, &Hash([0; 32])),
            RistrettoPoint::mul_base(&Scalar::from(100u64 - 10))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&bob, &Hash([55; 32])),
            RistrettoPoint::mul_base(&Scalar::from(2u64 - 2))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice, &Hash([0; 32])),
            RistrettoPoint::mul_base(&Scalar::from(0u64))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice, &Hash([55; 32])),
            RistrettoPoint::mul_base(&Scalar::from(0u64 + 2))
        );
    }
}
