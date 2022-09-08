extern crate criterion;
use criterion::{criterion_group, criterion_main, Criterion};

extern crate proteus;
use proteus::internal::keys::*;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("keygen", |b| b.iter(|| KeyPair::new()));
    group.finish();
}

fn bench_dh(c: &mut Criterion) {
    let x = KeyPair::new();
    let y = KeyPair::new();

    let mut group = c.benchmark_group("diffie-hellman");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("dh", |b| {
        b.iter(|| {
            let _sx = x.secret_key.shared_secret(&y.public_key);
        })
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let x = KeyPair::new();

    let mut group = c.benchmark_group("sign");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _s = x.secret_key.sign(b"foobarbaz");
        })
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let x = KeyPair::new();
    let s = x.secret_key.sign(b"foobarbaz");

    let mut group = c.benchmark_group("verify");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _r = x.public_key.verify(&s, b"foobarbaz");
        })
    });
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_dh, bench_sign, bench_verify);
criterion_main!(benches);
