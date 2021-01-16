/// Command line utility to be calles from 'LegalAge' certifier.
/// Generates a random nonce and computes the proverKey.
use harla_zk::api::Private;
use harla_zk::zk::{generate_prover_key, generate_random_private_key};
use std::env;
use std::str::FromStr;
use zokrates_field::{Bn128Field, Field};

fn bn128(s: &str) -> Bn128Field {
    Bn128Field::try_from_dec_str(s).unwrap()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        panic!("required 3 arguments");
    }
    let birthday = i32::from_str(&args[1]).unwrap();
    let photo_hash = bn128(&args[2]);
    let contract = bn128(&args[3]);
    let nonce = generate_random_private_key();

    let private = Private {
        birthday,
        nonce: nonce.clone(),
    };
    let prover_key = generate_prover_key(
        &private,
        &contract.into_byte_vector(),
        &photo_hash.into_byte_vector(),
    );

    println!(
        "{:?} {:?}",
        Bn128Field::from_byte_vector(nonce),
        Bn128Field::from_byte_vector(prover_key)
    );
}
