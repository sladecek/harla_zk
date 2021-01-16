/// Command line utility to be called from 'LegalAge' verifier.
/// Verifies a proof.
use harla_zk::api::{ProofQrCode, PublicChain};
use harla_zk::zk::verify_proof;
use std::env;
use std::fs;
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

    let qr_json = fs::read_to_string(&args[1]).unwrap();
    let qr = ProofQrCode::from_str(&qr_json).unwrap();
    let photo_hash = bn128(&args[2]);
    let prover_key = bn128(&args[3]);

    let chain_data = PublicChain {
        photo_hash: photo_hash.into_byte_vector(),
        prover_key: prover_key.into_byte_vector(),
    };
    //    println!("{}", qr.to_string());
    //    println!("{:?}", chain_data);
    let result = verify_proof(&qr, &chain_data).is_ok();
    println!("{}", if result { 1 } else { 0 });
}
