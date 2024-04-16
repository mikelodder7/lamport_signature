use criterion::*;
use lamport_signature_plus::{LamportFixedDigest, SigningKey, VerifyingKey};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use whirlpool::Whirlpool;

fn bench_whirlpool(c: &mut Criterion) {
    const DATA: &'static [u8] = b"hello, world!";

    c.bench_function("New Signing Key with Whirlpool", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let _ = SigningKey::<LamportFixedDigest<Whirlpool>>::random(rng);
        });
    });
    c.bench_function("Sign with Whirlpool", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Whirlpool>>::random(rng);
            sk.sign(DATA).unwrap();
        });
    });
    c.bench_function("Verify with Whirlpool", |b| {
        b.iter(|| {
            let rng = ChaChaRng::from_entropy();
            let mut sk = SigningKey::<LamportFixedDigest<Whirlpool>>::random(rng);
            let pk = VerifyingKey::from(&sk);
            let signature = sk.sign(DATA).unwrap();
            pk.verify(&signature, DATA).unwrap();
        });
    });
}

criterion_group!(benches, bench_whirlpool);

criterion_main!(benches);
