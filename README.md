# One-Time-Signatures

Rust implementation of simple Lamport and Winternitz one time signatures


## Usage

    use one_time_signatures_cry4::{LamportSecretKey, LamportPublicKey};
    use sha2::Sha256;

    let message = b"Hi There!";

    let mut sk = LamportSecretKey::<Sha256>::new();
    let pk = LamportPublicKey::<Sha256>::new(&sk);

    let sig = sk.sign_arbitrary(message).unwrap();
    pk.verify_arbitrary(message, &sig).unwrap();
    
## Benchmark

To build the benchmark file run:

    cargo build --features build-binary --bin benchmark
