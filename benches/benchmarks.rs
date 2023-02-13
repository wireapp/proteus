// Copyright (C) 2022 Wire Swiss GmbH <support@wire.com>
// Based on libsignal-protocol-java by Open Whisper Systems
// https://github.com/WhisperSystems/libsignal-protocol-java.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use criterion::{criterion_group, criterion_main, Criterion};

use proteus_wasm::internal::keys::*;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_function("keygen", |b| b.iter(|| KeyPair::new(None)));
    group.finish();
}

fn bench_dh(c: &mut Criterion) {
    let x = KeyPair::new(None);
    let y = KeyPair::new(None);

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
    let x = KeyPair::new(None);

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
    let x = KeyPair::new(None);
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

fn bench_verify_batched(c: &mut Criterion) {
    let x = KeyPair::new(None);
    const ITEMS: usize = 16;
    let mut inputs = std::collections::HashMap::new();
    use rand::Rng as _;
    for _ in 0..ITEMS {
        let message: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();
        inputs.insert(x.secret_key.sign(message.as_bytes()), message.into_bytes());
    }

    let mut group = c.benchmark_group("verify-batched-30l-16m");
    group.throughput(criterion::Throughput::Elements(ITEMS as u64));
    group.bench_with_input(
        criterion::BenchmarkId::new("batch-verify", "30-len message, 16 messages"),
        &inputs,
        |b, inputs| {
            b.iter(|| {
                for (sig, msg) in inputs {
                    let _r = x.public_key.verify(&sig, &msg);
                }
            })
        },
    );
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_dh,
    bench_sign,
    bench_verify,
    bench_verify_batched
);
criterion_main!(benches);
