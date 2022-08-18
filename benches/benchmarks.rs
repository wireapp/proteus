use criterion::{criterion_group, criterion_main, Criterion};
use proteus::internal::keys::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| b.iter(|| KeyPair::new()));
}

fn bench_dh(c: &mut Criterion) {
    let x = KeyPair::new();
    let y = KeyPair::new();
    c.bench_function("dh", |b| {
        b.iter(|| {
            let _sx = x.secret_key.shared_secret(&y.public_key);
        })
    });
}

fn bench_sign(c: &mut Criterion) {
    let x = KeyPair::new();
    c.bench_function("sign", |b| {
        b.iter(|| {
            let _s = x.secret_key.sign(b"foobarbaz");
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let x = KeyPair::new();
    let s = x.secret_key.sign(b"foobarbaz");
    c.bench_function("verify", |b| {
        b.iter(|| {
            let _r = x.public_key.verify(&s, b"foobarbaz");
        })
    });
}

criterion_group!(benches, bench_keygen, bench_dh, bench_sign, bench_verify);
criterion_main!(benches);
