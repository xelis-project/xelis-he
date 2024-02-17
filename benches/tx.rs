use criterion::{criterion_group, criterion_main, Criterion};
use elgamaltransactions::{
    builder::{TransactionBuilder, TransactionTypeBuilder, TransferBuilder},
    realistic_test::*,
    Hash, Transaction,
};
use std::iter;

fn n_tx_bench(c: &mut Criterion, n_transfers: usize) {
    let mut group = c.benchmark_group(&format!("Create verify n={n_transfers} transfers"));

    let bob = Account::new([(Hash([0; 32]), 100)]);
    let alice = Account::new([(Hash([0; 32]), 0)]);

    let ledger = Ledger {
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
            data: TransactionTypeBuilder::Transfer(
                iter::repeat_with(|| TransferBuilder {
                    dest_pubkey: alice,
                    amount: 1,
                    asset: Hash([0; 32]),
                    extra_data: Default::default(),
                })
                .take(n_transfers)
                .collect(),
            ),
            fee: 3,
            nonce: 1,
        };

        let mut state = GenerationBalance {
            balances: [(Hash([0; 32]), 100)].into(),
            account: ledger.get_account(&bob).clone(),
        };
        let keypair = &ledger.get_account(&bob).keypair;
        group.bench_with_input(
            "creation",
            &(builder.clone(), state.clone(), keypair),
            |bencher, (builder, state, keypair)| {
                let mut state = state.clone();
                bencher.iter(|| builder.clone().build(&mut state, *keypair).unwrap());
            },
        );

        builder.build(&mut state, keypair).unwrap()
    };

    group.bench_with_input("verification", &(tx, ledger), |bencher, (tx, ledger)| {
        bencher.iter(|| Transaction::verify(tx, &mut ledger.clone()).unwrap())
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
);

fn batching_bench_util(c: &mut Criterion, batch_size: usize) {
    let mut group = c.benchmark_group(&format!("Verify a batch of {batch_size} tx"));

    let bob = Account::new([(Hash([0; 32]), 100000)]);
    let alice = Account::new([(Hash([0; 32]), 0)]);

    let ledger = Ledger {
        accounts: [
            (bob.keypair.pubkey().compress(), bob.clone()),
            (alice.keypair.pubkey().compress(), alice.clone()),
        ]
        .into(),
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
            data: TransactionTypeBuilder::Transfer(vec![TransferBuilder {
                dest_pubkey: alice,
                amount: 1,
                asset: Hash([0; 32]),
                extra_data: Default::default(),
            }]),
            fee: 3,
            nonce: 1,
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

    group.bench_with_input("verification", &(txs, ledger), |bencher, (txs, ledger)| {
        bencher.iter(|| Transaction::verify_batch(&txs, &mut ledger.clone()).unwrap())
    });
}

fn batching_bench_1(c: &mut Criterion) {
    batching_bench_util(c, 1);
}

fn batching_bench_2(c: &mut Criterion) {
    batching_bench_util(c, 2);
}

fn batching_bench_4(c: &mut Criterion) {
    batching_bench_util(c, 4);
}

fn batching_bench_8(c: &mut Criterion) {
    batching_bench_util(c, 8);
}

fn batching_bench_16(c: &mut Criterion) {
    batching_bench_util(c, 16);
}

fn batching_bench_32(c: &mut Criterion) {
    batching_bench_util(c, 32);
}

fn batching_bench_64(c: &mut Criterion) {
    batching_bench_util(c, 64);
}

fn batching_bench_128(c: &mut Criterion) {
    batching_bench_util(c, 128);
}

fn batching_bench_256(c: &mut Criterion) {
    batching_bench_util(c, 256);
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
);

criterion_main!(create_verify_n_tx, batching_bench);
