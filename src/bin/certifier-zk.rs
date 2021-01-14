/// Command line utility to be calles from 'LegalAge' certifier.
/// Generates a random nonce and computes the proverKey.
use harla_zk::api::Private;
use harla_zk::zk::{generate_prover_key, generate_random_private_key};
use num_bigint::BigUint;
use std::env;
use std::str::FromStr;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        panic!("required 3 arguments");
    }
    let birthday = i32::from_str(&args[1]).unwrap();
    let photo_hash = BigUint::from_str(&args[2]).unwrap();
    let contract = BigUint::from_str(&args[3]).unwrap();
    let nonce = generate_random_private_key();

    let private = Private { birthday, nonce: nonce.clone() };
    let prover_key =
        generate_prover_key(&private, &contract.to_bytes_be(), &photo_hash.to_bytes_be());

    println!(
        "{} {}",
        BigUint::from_bytes_be(&nonce),
        BigUint::from_bytes_be(&prover_key)
    );
}
