# One-Time-Signatures

Rust implementation of simple Lamport and Winternitz one time signatures


## Usage

    let message = b"Hi There!";

    let mut sk = LamportSecretKey::<Sha256>::new();
    let pk = LamportPublicKey::<Sha256>::new(&sk);

    let sig = sk.sign_arbitrary(message).unwrap();
    pk.verify_arbitrary(message, &sig).unwrap();
