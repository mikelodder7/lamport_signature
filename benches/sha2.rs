use sha2::{Sha256, Sha384, Sha512};
use criterion::*;
use lamport_signature_plus::{LamportFixedDigest, SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

fn bench_sha256(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha256", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha256", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha256", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha256>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_sha384(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha384", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha384", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha384", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha384>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

fn bench_sha512(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Sha512", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
        });
    });
    c.bench_function("Sign with Sha512", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Sha512", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Sha512>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}


criterion_group!(benches, bench_sha256, bench_sha384, bench_sha512);

criterion_main!(benches);
