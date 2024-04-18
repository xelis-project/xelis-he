use thiserror::Error;

#[macro_use]
pub(crate) mod macros;

mod aead;
mod compressed;
mod elgamal;
pub(crate) mod proofs;
mod transcript;
mod tx;

pub use compressed::{CompressedCiphertext, CompressedPubkey, DecompressionError};
pub use elgamal::{
    ecdlp, DecryptHandle, ECDLPInstance, ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey,
    ElGamalSecretKey, PedersenCommitment, Signature,
};
pub use transcript::TranscriptError;
pub use tx::{builder, SmartContractCall, Transaction, TransactionType, Transfer};

pub use tx::BlockchainVerificationState;

// Re-export the curve25519_dalek types
pub use curve25519_dalek::{ristretto::RistrettoPoint, traits::Identity};

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

pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn is_zeros(&self) -> bool {
        self.0 == [0; 32]
    }
}

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("malformated ciphertext")]
pub struct CipherFormatError;

#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[error("transfer extra data decryption error")]
pub enum ExtraDataDecryptionError {
    Decompression(#[from] DecompressionError),
    Format(#[from] CipherFormatError),
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
    #[error("proof verification failed")]
    GenericProof,
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

// #[cfg(feature = "")]
pub mod realistic_test {
    use self::{builder::GetBlockchainAccountBalance, tx::BlockchainVerificationState};
    use super::*;
    use curve25519_dalek::RistrettoPoint;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct Ledger {
        pub accounts: HashMap<CompressedPubkey, Account>,
    }

    impl Ledger {
        pub fn get_account(&self, account: &CompressedPubkey) -> &Account {
            &self.accounts[account]
        }
        pub fn get_bal_decrypted(
            &self,
            account: &CompressedPubkey,
            asset: &Hash,
        ) -> RistrettoPoint {
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
            _role: Role,
        ) -> Result<CompressedCiphertext, Self::Error> {
            Ok(self.accounts[account].balances[asset])
        }

        fn update_account_balance(
            &mut self,
            account: &CompressedPubkey,
            asset: &Hash,
            new_ct: CompressedCiphertext,
            _role: Role,
        ) -> Result<(), Self::Error> {
            *self
                .accounts
                .get_mut(account)
                .unwrap()
                .balances
                .get_mut(asset)
                .unwrap() = new_ct;
            Ok(())
        }

        fn get_account_nonce(&self, account: &CompressedPubkey) -> Result<u64, Self::Error> {
            Ok(self.accounts[account].nonce)
        }

        fn update_account_nonce(
            &mut self,
            account: &CompressedPubkey,
            new_nonce: u64,
        ) -> Result<(), Self::Error> {
            self.accounts.get_mut(account).unwrap().nonce = new_nonce;
            Ok(())
        }

        fn set_output_ciphertext(
            &mut self,
            _output: &CompressedPubkey,
            _asset: &Hash,
            _ct: ElGamalCiphertext,
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone, Debug)]
    pub struct GenerationBalance {
        pub balances: HashMap<Hash, u64>,
        pub account: Account,
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
    pub struct Account {
        pub keypair: ElGamalKeypair,
        pub balances: HashMap<Hash, CompressedCiphertext>,
        pub nonce: u64,
    }

    impl Account {
        pub fn new(balances: impl IntoIterator<Item = (Hash, u64)>) -> Account {
            let keypair = ElGamalKeypair::keygen();

            Account {
                balances: balances
                    .into_iter()
                    .map(|(asset, balance)| (asset, keypair.pubkey().encrypt(balance).compress()))
                    .collect(),
                keypair,
                nonce: 0,
            }
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub mod tests {
    use crate::aead::PlaintextData;

    use self::tx::builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder};
    use super::realistic_test::*;
    use super::*;
    use curve25519_dalek::{RistrettoPoint, Scalar};

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
                nonce: 0,
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
                nonce: 0,
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
    fn encrypt_extra_data() {
        let bob = Account::new([(Hash([0; 32]), 100), (Hash([55; 32]), 2)]);
        let alice = Account::new([(Hash([0; 32]), 0), (Hash([55; 32]), 0)]);

        let ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
            ]
            .into(),
        };

        let bob_pk = bob.keypair.pubkey().compress();
        let alice_pk = alice.keypair.pubkey().compress();

        let very_secret_message: Vec<u8> =
            "hi, this is the president talking. i have top secret intel i need to share with you"
                .into();

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: bob_pk,
                data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                    dest_pubkey: alice_pk,
                    amount: 2,
                    asset: Hash([55; 32]),
                    extra_data: Some(PlaintextData(very_secret_message.clone())),
                }]),
                fee: 10,
                nonce: 0,
            };
            assert_eq!(10, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(2, builder.get_transaction_cost(&Hash([55; 32])));

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100), (Hash([55; 32]), 2)].into(),
                        account: ledger.get_account(&bob_pk).clone(),
                    },
                    &ledger.get_account(&bob_pk).keypair,
                )
                .unwrap()
        };

        let TransactionType::Transfer(transfers) = tx.get_data() else {
            unreachable!()
        };

        assert_eq!(
            transfers[0].clone()
                .decrypt_extra_data_in_place(alice.keypair.secret(), Role::Receiver)
                .unwrap()
                .unwrap()
                .0,
            very_secret_message
        );

        assert_eq!(
            transfers[0].clone()
                .decrypt_extra_data_in_place(bob.keypair.secret(), Role::Sender)
                .unwrap()
                .unwrap()
                .0,
            very_secret_message
        );

        assert_eq!(
            transfers[0].clone()
                .decrypt_extra_data(bob.keypair.secret(), Role::Sender)
                .unwrap()
                .unwrap()
                .0,
            very_secret_message
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
                data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                    dest_pubkey: alice,
                    amount: 2,
                    asset: Hash([55; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 10,
                nonce: 0,
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
