use thiserror::Error;

#[macro_use]
pub(crate) mod macros;

mod extra_data;
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
    #[error("invalid signature")]
    Signature,
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

pub mod mock {
    use super::*;
    use self::{
        builder::GetBlockchainAccountBalance,
        tx::BlockchainVerificationState
    };
    use curve25519_dalek::RistrettoPoint;
    use std::collections::HashMap;

    #[derive(Debug, Clone)]
    pub struct Ledger {
        pub accounts: HashMap<CompressedPubkey, Account>,
        pub multisig_accounts: HashMap<CompressedPubkey, (Vec<CompressedPubkey>, u8)>,
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

        fn set_multisig_for_account(
            &mut self,
            account: &CompressedPubkey,
            signers: &Vec<CompressedPubkey>,
            threshold: u8,
        ) -> Result<(), Self::Error> {
            if signers.is_empty() {
                self.multisig_accounts.remove(account);
            } else {
                self.multisig_accounts.insert(account.clone(), (signers.clone(), threshold));
            }
            Ok(())
        }

        fn get_multisig_for_account(
                &self,
                account: &CompressedPubkey,
            ) -> Result<Option<(Vec<CompressedPubkey>, u8)>, Self::Error> {
            Ok(self.multisig_accounts.get(account).cloned())
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

#[cfg(test)]
pub mod tests {
    use super::*;
    use self::{
        extra_data::PlaintextData,
        tx::builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder}
    };
    use mock::*;
    use curve25519_dalek::{RistrettoPoint, Scalar};

    #[test]
    fn test_invalid_multisig() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let bob = Account::new([(Hash([0; 32]), 0)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
                    dest_pubkey: bob.keypair.pubkey().compress(),
                    amount: 10,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (bob.keypair.pubkey().compress(), bob.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        Transaction::verify(&tx, &mut ledger.clone()).unwrap();

        // Add multisig
        ledger.set_multisig_for_account(
            &alice.keypair.pubkey().compress(),
            &vec![charlie.keypair.pubkey().compress()],
            1,
        )
        .unwrap();

        assert!(Transaction::verify(&tx, &mut ledger).is_err());
    }

    #[test]
    fn test_multisig() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let bob = Account::new([(Hash([0; 32]), 0)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
                    dest_pubkey: bob.keypair.pubkey().compress(),
                    amount: 10,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            let mut unsigned = builder
                .build_unsigned(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap();

            let hash = unsigned.hash();
            let signature = charlie.keypair.sign(&hash.0);
            unsigned.set_multisig(vec![(0, signature)]);
            unsigned.sign(&alice.keypair)
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (bob.keypair.pubkey().compress(), bob.clone()),
                (charlie.keypair.pubkey().compress(), charlie.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        // Add multisig
        ledger.set_multisig_for_account(
            &alice.keypair.pubkey().compress(),
            &vec![charlie.keypair.pubkey().compress()],
            1,
        )
        .unwrap();

        Transaction::verify(&tx, &mut ledger).unwrap();
    }

    #[test]
    fn test_multisig_threshold_2() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let bob = Account::new([(Hash([0; 32]), 0)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);
        let dave = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
                    dest_pubkey: bob.keypair.pubkey().compress(),
                    amount: 10,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            let mut unsigned = builder
                .build_unsigned(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap();

            let hash = unsigned.hash();
            let signature1 = charlie.keypair.sign(&hash.0);
            let signature2 = dave.keypair.sign(&hash.0);
            unsigned.set_multisig(vec![(0, signature1), (1, signature2)]);
            unsigned.sign(&alice.keypair)
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (bob.keypair.pubkey().compress(), bob.clone()),
                (charlie.keypair.pubkey().compress(), charlie.clone()),
                (dave.keypair.pubkey().compress(), dave.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        // Add multisig
        ledger.set_multisig_for_account(
            &alice.keypair.pubkey().compress(),
            &vec![charlie.keypair.pubkey().compress(), dave.keypair.pubkey().compress()],
            2,
        )
        .unwrap();

        Transaction::verify(&tx, &mut ledger).unwrap();
    }

    #[test]
    fn test_multisig_threshold_one_on_two_signers() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let bob = Account::new([(Hash([0; 32]), 0)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);
        let dave = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
                    dest_pubkey: bob.keypair.pubkey().compress(),
                    amount: 10,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                }]),
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            let mut unsigned = builder
                .build_unsigned(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap();

            let hash = unsigned.hash();
            let signature1 = dave.keypair.sign(&hash.0);
            unsigned.set_multisig(vec![(1, signature1)]);
            unsigned.sign(&alice.keypair)
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (bob.keypair.pubkey().compress(), bob.clone()),
                (charlie.keypair.pubkey().compress(), charlie.clone()),
                (dave.keypair.pubkey().compress(), dave.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        // Add multisig
        // One of the two signers is enough
        ledger.set_multisig_for_account(
            &alice.keypair.pubkey().compress(),
            &vec![charlie.keypair.pubkey().compress(), dave.keypair.pubkey().compress()],
            1,
        )
        .unwrap();

        Transaction::verify(&tx, &mut ledger).unwrap();
    }

    #[test]
    fn test_multisig_setup() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let bob = Account::new([(Hash([0; 32]), 0)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);
        let dave = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::MultiSig {
                    signers: vec![
                        charlie.keypair.pubkey().compress(),
                        dave.keypair.pubkey().compress(),
                    ],
                    threshold: 2,
                },
                fee: 1,
                nonce: 0,
            };

            assert_eq!(1, builder.get_transaction_cost(&Hash([0; 32])));

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (bob.keypair.pubkey().compress(), bob.clone()),
                (charlie.keypair.pubkey().compress(), charlie.clone()),
                (dave.keypair.pubkey().compress(), dave.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        Transaction::verify(&tx, &mut ledger).unwrap();

        assert_eq!(
            ledger.get_multisig_for_account(&alice.keypair.pubkey().compress()).unwrap(),
            Some((
                vec![
                    charlie.keypair.pubkey().compress(),
                    dave.keypair.pubkey().compress()
                ],
                2
            ))
        );
    }

    #[test]
    fn test_multisig_delete() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let charlie = Account::new([(Hash([0; 32]), 0)]);
        let dave = Account::new([(Hash([0; 32]), 0)]);

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::MultiSig {
                    signers: vec![],
                    threshold: 0,
                },
                fee: 1,
                nonce: 0,
            };

            assert_eq!(1, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            let mut unsigned = builder
                .build_unsigned(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap();

            let hash = unsigned.hash();
            let signature1 = charlie.keypair.sign(&hash.0);
            let signature2 = dave.keypair.sign(&hash.0);
            unsigned.set_multisig(vec![(0, signature1), (1, signature2)]);
            unsigned.sign(&alice.keypair)
        };

        let mut ledger = Ledger {
            accounts: [
                (alice.keypair.pubkey().compress(), alice.clone()),
                (charlie.keypair.pubkey().compress(), charlie.clone()),
                (dave.keypair.pubkey().compress(), dave.clone()),
            ].into(),
            multisig_accounts: Default::default(),
        };

        // Add multisig
        ledger.set_multisig_for_account(
            &alice.keypair.pubkey().compress(),
            &vec![charlie.keypair.pubkey().compress(), dave.keypair.pubkey().compress()],
            2,
        )
        .unwrap();

        Transaction::verify(&tx, &mut ledger).unwrap();

        assert_eq!(
            ledger.get_multisig_for_account(&alice.keypair.pubkey().compress()).unwrap(),
            None
        );
    }

    #[test]
    fn test_burn() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Burn {
                    asset: Hash([0; 32]),
                    amount: 10,
                },
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let mut ledger = Ledger {
            accounts: [(alice.keypair.pubkey().compress(), alice.clone())].into(),
            multisig_accounts: Default::default(),
        };

        Transaction::verify_batch(&vec![tx], &mut ledger).unwrap();

        assert_eq!(
            ledger.get_bal_decrypted(&alice.keypair.pubkey().compress(), &Hash([0; 32])),
            // 10 for burn and 1 for fee
            RistrettoPoint::mul_base(&Scalar::from(100u64 - 11))
        );
    }

    #[test]
    fn test_burn_non_native_asset() {
        let alice = Account::new([(Hash([0; 32]), 1), (Hash([55; 32]), 50)]);
        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Burn {
                    asset: Hash([55; 32]),
                    amount: 50,
                },
                fee: 1,
                nonce: 0,
            };

            assert_eq!(1, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(50, builder.get_transaction_cost(&Hash([55; 32])));

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 1), (Hash([55; 32]), 50)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let mut ledger = Ledger {
            accounts: [(alice.keypair.pubkey().compress(), alice.clone())].into(),
            multisig_accounts: Default::default(),
        };

        Transaction::verify_batch(&vec![tx], &mut ledger).unwrap();

        assert_eq!(
            ledger.get_bal_decrypted(&alice.keypair.pubkey().compress(), &Hash([0; 32])),
            // - 1 for fee
            RistrettoPoint::mul_base(&Scalar::from(0u64))
        );
        assert_eq!(
            ledger.get_bal_decrypted(&alice.keypair.pubkey().compress(), &Hash([55; 32])),
            // 50-50 for burn
            RistrettoPoint::mul_base(&Scalar::from(0u64))
        );
    }

    #[test]
    fn test_invalid_burn() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let mut tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Burn {
                    asset: Hash([0; 32]),
                    amount: 100,
                },
                fee: 0,
                nonce: 0,
            };

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let ledger = Ledger {
            accounts: [(alice.keypair.pubkey().compress(), alice.clone())].into(),
            multisig_accounts: Default::default(),
        };

        assert!(Transaction::verify(&tx, &mut ledger.clone()).is_ok());

        // Change burn amount
        tx.data = TransactionType::Burn {
            asset: Hash([0; 32]),
            amount: 101,
        };

        assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());

        // Change burn asset
        tx.data = TransactionType::Burn {
            asset: Hash([1; 32]),
            amount: 100,
        };

        assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());
    }

    #[test]
    fn test_invalid_transfer_tx() {
        let alice = Account::new([(Hash([0; 32]), 100)]);
        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: alice.keypair.pubkey().compress(),
                data: TransactionTypeBuilder::Burn {
                    asset: Hash([0; 32]),
                    amount: 10,
                },
                fee: 1,
                nonce: 0,
            };

            assert_eq!(11, builder.get_transaction_cost(&Hash([0; 32])));
            assert_eq!(1, builder.used_assets().len());

            builder
                .build(
                    &mut GenerationBalance {
                        balances: [(Hash([0; 32]), 100)].into(),
                        account: alice.clone(),
                    },
                    &alice.keypair,
                )
                .unwrap()
        };

        let ledger = Ledger {
            accounts: [(alice.keypair.pubkey().compress(), alice.clone())].into(),
            multisig_accounts: Default::default(),
        };

        // Tx without change is valid
        assert!(Transaction::verify(&tx, &mut ledger.clone()).is_ok());

        // Verify signature
        {
            let mut tx = tx.clone();
            tx.signature = Signature::new(Scalar::from(0u64), Scalar::from(0u64));

            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());
        }

        // Verify source commitments
        {
            let mut tx = tx.clone();
            tx.new_source_commitments[0].asset = Hash([1; 32]);

            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());

            tx.new_source_commitments.clear();
            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());
        }

        // Verify fee
        {
            let mut tx = tx.clone();
            tx.fee = 0;

            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());

            tx.fee = 12;
            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());
        }

        // Verify nonce
        {
            let mut tx = tx.clone();
            tx.nonce = 1;

            assert!(Transaction::verify(&tx, &mut ledger.clone()).is_err());
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
            multisig_accounts: Default::default(),
        };

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();
        let eve = eve.keypair.pubkey().compress();

        let tx1 = {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfers(vec![
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
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
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
            multisig_accounts: Default::default(),
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
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
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

        let TransactionType::Transfers(transfers) = tx.get_data() else {
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
            multisig_accounts: Default::default(),
        };

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();

        let tx = {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfers(vec![TransferBuilder {
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
