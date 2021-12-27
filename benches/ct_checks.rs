extern crate dudect_bencher;
extern crate rand;

use dudect_bencher::{ctbench_main, ctbench_main_with_seeds, BenchRng, CtRunner, Class};
use rand::Rng;

const INPUTS_QTY: usize = 1_000_000;

fn test_is_pk_eq_ct(runner: &mut CtRunner, rng: &mut BenchRng) {
    let mut inputs = Vec::with_capacity(INPUTS_QTY);
    let mut classes = Vec::with_capacity(INPUTS_QTY);
    for _ in 0..INPUTS_QTY {
        if rng.gen::<bool>() {
            inputs.push((
                proteus::internal::keys::KeyPair::new().public_key,
                proteus::internal::keys::KeyPair::new().public_key,
            ));
            classes.push(Class::Left);
        } else {
            let pk = proteus::internal::keys::KeyPair::new().public_key;
            let pk2 = pk.clone();
            inputs.push((pk, pk2));
            classes.push(Class::Right);
        }
    }

    for (class, (k1, k2)) in classes.into_iter().zip(inputs.into_iter()) {
        runner.run_one(class, || k1 == k2);
    }
}

ctbench_main!(test_is_pk_eq_ct);
