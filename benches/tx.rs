use criterion::{criterion_group, criterion_main, Criterion};
use std::{iter, thread};
use xelis_he::{
    builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
    Hash,
    Transaction,
    mock::*,
};

fn n_tx_bench(c: &mut Criterion, n_transfers: usize) {
    let mut group = c.benchmark_group(&format!("Create verify n={n_transfers} transfers"));

    let make_builder = || {
        let bob = Account::new([(Hash([0; 32]), 10000000)]);
        let alice = Account::new([(Hash([0; 32]), 0)]);

        let ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
            ]
            .into(),
            multisig_accounts: Default::default(),
        };

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();

        let builder = TransactionBuilder {
            version: 1,
            source: bob,
            data: TransactionTypeBuilder::Transfers(
                iter::repeat_with(|| TransferBuilder {
                    dest_pubkey: alice,
                    amount: 1,
                    asset: Hash([0; 32]),
                    extra_data: None,
                })
                .take(n_transfers)
                .collect(),
            ),
            fee: 3,
            nonce: 0,
        };

        let state = GenerationBalance {
            balances: [(Hash([0; 32]), 10000000)].into(),
            account: ledger.get_account(&bob).clone(),
        };

        (builder, state, ledger, bob)
    };

    group.bench_function("creation", |bencher| {
        let (builder, mut state, ledger, bob) = make_builder();
        let keypair = &ledger.get_account(&bob).keypair;
        bencher.iter(|| builder.clone().build(&mut state, keypair).unwrap());
    });

    group.bench_function("verification", |bencher| {
        let (builder, mut state, ledger, bob) = make_builder();
        let keypair = &ledger.get_account(&bob).keypair;
        let tx = builder.build(&mut state, keypair).unwrap();
        bencher.iter(|| Transaction::verify(&tx, &mut ledger.clone()).unwrap())
    });
}

fn n_tx_bench_1(c: &mut Criterion) {
    n_tx_bench(c, 1);
}

fn n_tx_bench_2(c: &mut Criterion) {
    n_tx_bench(c, 2);
}

fn n_tx_bench_3(c: &mut Criterion) {
    n_tx_bench(c, 3);
}

fn n_tx_bench_4(c: &mut Criterion) {
    n_tx_bench(c, 4);
}

fn n_tx_bench_5(c: &mut Criterion) {
    n_tx_bench(c, 5);
}

fn n_tx_bench_6(c: &mut Criterion) {
    n_tx_bench(c, 6);
}

fn n_tx_bench_7(c: &mut Criterion) {
    n_tx_bench(c, 7);
}

fn n_tx_bench_8(c: &mut Criterion) {
    n_tx_bench(c, 8);
}

fn n_tx_bench_12(c: &mut Criterion) {
    n_tx_bench(c, 12);
}

fn n_tx_bench_16(c: &mut Criterion) {
    n_tx_bench(c, 16);
}

fn n_tx_bench_255(c: &mut Criterion) {
    n_tx_bench(c, 255);
}

criterion_group!(
    name = create_verify_n_tx;
    config = Criterion::default();
    targets =
        n_tx_bench_1,
        n_tx_bench_2,
        n_tx_bench_3,
        n_tx_bench_4,
        n_tx_bench_5,
        n_tx_bench_6,
        n_tx_bench_7,
        n_tx_bench_8,
        n_tx_bench_12,
        n_tx_bench_16,
        n_tx_bench_255,
);

fn batching_bench_util(c: &mut Criterion, batch_size: usize, n_transfers: usize) {
    let mut group = c.benchmark_group(&format!("Verify a batch of {batch_size} tx with {n_transfers} transfers"));

    group.bench_function("verification", |bencher| {
        let bob = Account::new([(Hash([0; 32]), 100000)]);
        let alice = Account::new([(Hash([0; 32]), 0)]);

        let ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
            ]
            .into(),
            multisig_accounts: Default::default(),
        };
        let mut prover_ledger = ledger.clone();

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();

        let mut state = GenerationBalance {
            balances: [(Hash([0; 32]), 100000)].into(),
            account: ledger.get_account(&bob).clone(),
        };
        let make_tx = || {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfers(
                    iter::repeat_with(|| TransferBuilder {
                        dest_pubkey: alice,
                        amount: 1,
                        asset: Hash([0; 32]),
                        extra_data: None,
                    })
                    .take(n_transfers)
                    .collect(),
                ),
                fee: 3,
                nonce: 0,
            };

            let cost = builder.get_transaction_cost(&Hash([0; 32]));

            let keypair = &ledger.get_account(&bob).keypair;
            let tx = builder.build(&mut state, keypair).unwrap();

            tx.apply_without_verify(&mut prover_ledger).unwrap();

            *state.balances.get_mut(&Hash([0; 32])).unwrap() -= cost;
            state.account = prover_ledger.get_account(&bob).clone();

            tx
        };

        let txs = iter::repeat_with(make_tx)
            .take(batch_size)
            .collect::<Vec<_>>();
        bencher.iter(|| Transaction::verify_batch(&txs, &mut ledger.clone()).unwrap())
    });
}

fn batching_bench_1(c: &mut Criterion) {
    batching_bench_util(c, 1, 1);
}

fn batching_bench_2(c: &mut Criterion) {
    batching_bench_util(c, 2, 1);
}

fn batching_bench_4(c: &mut Criterion) {
    batching_bench_util(c, 4, 1);
}

fn batching_bench_8(c: &mut Criterion) {
    batching_bench_util(c, 8, 1);
}

fn batching_bench_16(c: &mut Criterion) {
    batching_bench_util(c, 16, 1);
}

fn batching_bench_32(c: &mut Criterion) {
    batching_bench_util(c, 32, 1);
}

fn batching_bench_64(c: &mut Criterion) {
    batching_bench_util(c, 64, 1);
}

fn batching_bench_128(c: &mut Criterion) {
    batching_bench_util(c, 128, 1);
}

fn batching_bench_256(c: &mut Criterion) {
    batching_bench_util(c, 256, 1);
}

fn batching_bench_2500(c: &mut Criterion) {
    batching_bench_util(c, 2500, 1);
}

fn batching_bench_16x255(c: &mut Criterion) {
    batching_bench_util(c, 16, 255);
}

criterion_group!(
    name = batching_bench;
    config = Criterion::default();
    targets =
        batching_bench_1,
        batching_bench_2,
        batching_bench_4,
        batching_bench_8,
        batching_bench_16,
        batching_bench_32,
        batching_bench_64,
        batching_bench_128,
        batching_bench_256,
        batching_bench_2500,
        batching_bench_16x255
);

fn batching_bench_multi_util(c: &mut Criterion, batch_size: usize, n_transfers: usize, n_threads: usize) {
    let mut group = c.benchmark_group(&format!("Verify a batch of {batch_size} tx ({n_threads} threads) with {n_transfers} transfers"));

    group.bench_function("verification", |bencher| {
        let bob = Account::new([(Hash([0; 32]), 100000)]);
        let alice = Account::new([(Hash([0; 32]), 0)]);

        let ledger = Ledger {
            accounts: [
                (bob.keypair.pubkey().compress(), bob.clone()),
                (alice.keypair.pubkey().compress(), alice.clone()),
            ]
            .into(),
            multisig_accounts: Default::default(),
        };
        let mut prover_ledger = ledger.clone();

        let bob = bob.keypair.pubkey().compress();
        let alice = alice.keypair.pubkey().compress();

        let mut state = GenerationBalance {
            balances: [(Hash([0; 32]), 100000)].into(),
            account: ledger.get_account(&bob).clone(),
        };
        let make_tx = || {
            let builder = TransactionBuilder {
                version: 1,
                source: bob,
                data: TransactionTypeBuilder::Transfers(
                    iter::repeat_with(|| TransferBuilder {
                        dest_pubkey: alice,
                        amount: 1,
                        asset: Hash([0; 32]),
                        extra_data: None,
                    })
                    .take(n_transfers)
                    .collect(),
                ),
                fee: 3,
                nonce: 0,
            };

            let cost = builder.get_transaction_cost(&Hash([0; 32]));

            let keypair = &ledger.get_account(&bob).keypair;
            let tx = builder.build(&mut state, keypair).unwrap();

            tx.apply_without_verify(&mut prover_ledger).unwrap();

            *state.balances.get_mut(&Hash([0; 32])).unwrap() -= cost;
            state.account = prover_ledger.get_account(&bob).clone();

            tx
        };

        let groups = iter::repeat_n(
                iter::repeat_with(make_tx)
                            .take(batch_size)
                            .collect::<Vec<_>>(),
        n_threads)
            .collect::<Vec<_>>();

        bencher.iter(|| {
            let mut handles = Vec::with_capacity(n_threads);
            for txs in groups.clone() {
                let mut ledger = ledger.clone();
                let handle = thread::spawn(move || Transaction::verify_batch(&txs, &mut ledger).unwrap());
                handles.push(handle);
            }

            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

fn batching_bench_multi_2500(c: &mut Criterion) {
    batching_bench_multi_util(c, 2500, 1, 8);
}

fn batching_bench_multi_16x255(c: &mut Criterion) {
    batching_bench_multi_util(c, 16, 255, 8);
}

criterion_group!(
    name = batching_bench_multi;
    config = Criterion::default().sample_size(10);
    targets =
    batching_bench_multi_2500,
    batching_bench_multi_16x255,
);

criterion_main!(create_verify_n_tx, batching_bench, batching_bench_multi);
