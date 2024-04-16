use blake2::{Blake2b512, Blake2s256};
use criterion::*;
use lamport_signature_plus::{LamportFixedDigest, SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

fn bench_blake2s(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Blake2s", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Blake2s256>>::random(rng);
        });
    });
    c.bench_function("Sign with Blake2s", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Blake2s256>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Blake2s", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Blake2s256>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_blake2b(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Blake2b", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Blake2b512>>::random(rng);
        });
    });
    c.bench_function("Sign with Blake2b", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Blake2b512>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Blake2b512", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Blake2b512>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

criterion_group!(benches, bench_blake2s, bench_blake2b);

criterion_main!(benches);