use sha2::{Digest, Sha256};
use rand::{thread_rng, RngCore};
use std::time::Instant;
use one_time_signatures_cry4::{LamportPublicKey, LamportSecretKey, WinternitzPublicKey, WinternitzSecretKey};
use itertools::izip;

struct BenchResults {
    keygen_times: Vec<u128>,
    signing_times: Vec<u128>,
    verifying_times: Vec<u128>,
}

#[allow(dead_code)]
fn lamport_bench<D: Digest>(i: usize) -> BenchResults {
    let mut sk;
    let mut pk;
    let mut sig;
    let mut kgs = Vec::with_capacity(i);
    let mut sgs = Vec::with_capacity(i);
    let mut ves = Vec::with_capacity(i);
    #[allow(non_snake_case)]
    let TEST_MESSAGE = &mut [0u8; 32];

    for _ in 0..i {
        thread_rng().fill_bytes(TEST_MESSAGE);
        let now = Instant::now();
        sk = LamportSecretKey::<D>::new();
        pk = LamportPublicKey::<D>::new(&sk);
        let elapsed = now.elapsed();
        kgs.push(elapsed.as_micros());

        let now = Instant::now();
        sig = sk.sign(TEST_MESSAGE).unwrap();
        let elapsed = now.elapsed();
        sgs.push(elapsed.as_micros());

        let now = Instant::now();
        pk.verify(TEST_MESSAGE, &sig).unwrap();
        let elapsed = now.elapsed();
        ves.push(elapsed.as_micros());
    }

    let a = 1000.0;
    if i == 1 {
            let av_kg = kgs.iter().sum::<u128>() as f64 / i as f64;
            let av_sig = sgs.iter().sum::<u128>() as f64 / i as f64;
            let av_ver = ves.iter().sum::<u128>() as f64 / i as f64;
            println!("With a single Lamport run, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", av_kg / a, av_sig / a, av_ver / a);
    }

    BenchResults { keygen_times: kgs, signing_times: sgs, verifying_times: ves }
}

#[allow(dead_code)]
fn winternitz_bench<D: Digest>(i: usize, w: usize) -> BenchResults {
    let mut sk;
    let mut pk;
    let mut sig;
    let mut kgs = Vec::with_capacity(i);
    let mut sgs = Vec::with_capacity(i);
    let mut ves = Vec::with_capacity(i);
    #[allow(non_snake_case)]
    let TEST_MESSAGE = &mut [0u8; 32];

    for _ in 0..i {
        thread_rng().fill_bytes(TEST_MESSAGE);
        let now = Instant::now();
        sk = WinternitzSecretKey::<D>::new(w);
        pk = WinternitzPublicKey::<D>::new(&sk);
        let elapsed = now.elapsed();
        kgs.push(elapsed.as_micros());

        let now = Instant::now();
        sig = sk.sign(TEST_MESSAGE).unwrap();
        let elapsed = now.elapsed();
        sgs.push(elapsed.as_micros());

        let now = Instant::now();
        pk.verify(TEST_MESSAGE, &sig).unwrap();
        let elapsed = now.elapsed();
        ves.push(elapsed.as_micros());
    }

    let a = 1000.0;
    if i == 1 {
            let av_kg = kgs.iter().sum::<u128>() as f64 / i as f64;
            let av_sig = sgs.iter().sum::<u128>() as f64 / i as f64;
            let av_ver = ves.iter().sum::<u128>() as f64 / i as f64;
            println!("With a single Winternitz run, the times are\nKeygen:\t\t{:.3?}\nSigning:\t{:.3?}\nVerifying:\t{:.3?}", av_kg / a, av_sig / a, av_ver / a);
    }

    BenchResults { keygen_times: kgs, signing_times: sgs, verifying_times: ves }
}

fn main() {
    let path = "";
    let iterations = 100;

    //let bench_res = lamport_bench::<Sha256>(iterations);
    let bench_res = winternitz_bench::<Sha256>(iterations, 256);
 
    let formatted_data = izip!(&bench_res.keygen_times, &bench_res.signing_times, &bench_res.verifying_times)
        .fold(String::from(""), |acc, (&kg, &sign, &ver)| acc + format!("{:.3?}\t{:.3?}\t{:.3?}\n", kg as f64 / 1000.0, sign as f64 / 1000.0, ver as f64 / 1000.0).as_str());
    let contents = format!("{} with {} iterations\nkeygen\tsigning\tverifying\n{}", "Lamport", iterations, formatted_data);

    use std::fs;
    fs::write(path, contents).unwrap();
}