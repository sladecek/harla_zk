// Zero-knowledge algorithms.

use crate::api::{Private, ProofQrCode, PublicChain, QrError, QrRequest, Relation};

use bellman_ce::groth16::Proof as BellmanProof;
use bellman_ce::pairing::{bn256::Bn256, ff::ScalarEngine};
use ff_mimc::{PrimeField, PrimeFieldRepr};
use rand::{thread_rng, ChaChaRng, Rng, SeedableRng};
use std::io::Cursor;
use zokrates_core::ir::{self, ProgEnum};
use zokrates_core::proof_system::{
    bellman::groth16::{ProofPoints, G16},
    Proof, ProofSystem,
};
use zokrates_core::typed_absy::abi::Abi;
use zokrates_field::{Bn128Field, Field};

static PROGRAM: &[u8] = include_bytes!("../zokrates/out");
static ABI: &[u8] = include_bytes!("../zokrates/abi.json");
static PROVING_KEY: &[u8] = include_bytes!("../zokrates/proving.key");
static VERIFICATION_KEY: &[u8] = include_bytes!("../zokrates/verification.key");

type Fr = <Bn256 as ScalarEngine>::Fr;

pub fn generate_random_private_key() -> Vec<u8> {
    let seed = thread_rng().gen::<[u32; 4]>();
    let mut rng = ChaChaRng::from_seed(&seed);
    let r: Fr = rng.gen();
    Bn128Field::from_bellman(r).into_byte_vector()
}

fn zok2mimc(value: &Bn128Field) -> mimc_rs::Fr {
    // Zokrates uses internal BigInt representation, mimc uses ff with private Repr.
    let s = value.to_dec_string();
    mimc_rs::Fr::from_str(&s).unwrap()
}

fn mimc2zok(value: mimc_rs::Fr) -> Bn128Field {
    let mut res: Vec<u8> = vec![];
    value.into_repr().write_le(&mut res).unwrap();
    Bn128Field::from_byte_vector(res)
}

fn compute_mimc7r10_hash(x: &Bn128Field, k: &Bn128Field) -> Bn128Field {
    let mimc7r10 = mimc_rs::Mimc7::new(10);
    let hash = mimc7r10.hash(&zok2mimc(x), &zok2mimc(k));
    mimc2zok(hash)
}

pub fn generate_prover_key(private: Private, contract: Vec<u8>, photo_hash: Vec<u8>) -> Vec<u8> {
    let nonce = Bn128Field::from_byte_vector(private.nonce);
    let birthday = Bn128Field::from(private.birthday);
    let photo_hash = Bn128Field::from_byte_vector(photo_hash);
    let contract = Bn128Field::from_byte_vector(contract);

    let card_key = compute_mimc7r10_hash(&(birthday + nonce), &(photo_hash * contract));
    card_key.into_byte_vector()
}

pub fn generate_proof(rq: QrRequest) -> Result<ProofQrCode, String> {
    let prg = match ProgEnum::deserialize(&mut PROGRAM.clone())? {
        ProgEnum::Bn128Program(p) => p,
        _ => panic!("Invalid program type"),
    };

    let abi: Abi = serde_json::from_reader(&mut ABI.clone()).unwrap();
    let _signature = abi.signature();

    let interpreter = ir::Interpreter::default();

    let mut arguments: Vec<Bn128Field> = Vec::new();

    let birthday = rq.private.birthday;
    let mut delta = rq.qr.delta;
    let today = rq.qr.today;

    let mut is_younger = 0;

    if rq.is_relation_valid() {
        if rq.qr.relation == Relation::Younger {
            is_younger = 1;
        }
    } else {
        // Generating invalid proof.
        //
        // The user wants us to proof something what is not
        // true. Maybe someone is trying to abuse the phone to learn
        // about the user's age. We do not want to report an error because
        // this will allow annyone to guess the age by trial and
        // error. Instead we will generate a valid proof but for
        // another set of input variables. The proof will fail to be
        // verified but it will look similar to a real proof and the
        // generation will take about the same time.
        delta = 0;
    }

    arguments.push(Bn128Field::from(birthday));
    arguments.push(Bn128Field::from(delta));
    arguments.push(Bn128Field::from(today));
    arguments.push(Bn128Field::from(is_younger));
    arguments.push(Bn128Field::from_byte_vector(rq.chain.photo_hash.clone()));
    arguments.push(Bn128Field::from_byte_vector(rq.qr.contract.clone()));
    arguments.push(Bn128Field::from_byte_vector(rq.private.nonce));

    let witness = interpreter
        .execute(&prg, &arguments)
        .map_err(|e| format!("Execution failed: {}", e))?;

    let outs = witness.return_values();
    assert_eq!(1, outs.len());
    //let out = &outs[0];

    let proof = G16::generate_proof(prg, witness, PROVING_KEY.to_vec());
    let proof = &proof.proof.into_bellman::<Bn128Field>();
    let mut proof_bytes: Vec<u8> = Vec::new();
    proof.write(&mut proof_bytes).unwrap();

    let qr = ProofQrCode {
        public: rq.qr,
        proof: proof_bytes,
    };
    Ok(qr)
}

pub fn verify_proof(qr: &ProofQrCode, chain: &PublicChain) -> Result<(), String> {
    let vk = serde_json::from_reader(VERIFICATION_KEY)
        .map_err(|why| format!("Couldn't deserialize verification key: {}", why))?;

    let mut inputs: Vec<Bn128Field> = Vec::new();

    // Inverting the relation.
    let delta = qr.public.delta;
    let today = qr.public.today;
    let is_younger = qr.public.relation == Relation::Younger;

    inputs.push(Bn128Field::from(delta));
    inputs.push(Bn128Field::from(today));
    inputs.push(Bn128Field::from(if is_younger { 1 } else { 0 }));
    inputs.push(Bn128Field::from_byte_vector(chain.photo_hash.clone()));
    inputs.push(Bn128Field::from_byte_vector(qr.public.contract.clone()));

    inputs.push(Bn128Field::from_byte_vector(chain.prover_key.clone()));

    let mut rdr = Cursor::new(&qr.proof);
    let proof = BellmanProof::<Bn256>::read(&mut rdr)
        .map_err(|_| QrError {})
        .unwrap();

    let mut raw: Vec<u8> = Vec::new();
    proof.write(&mut raw).unwrap();

    let proof_points = ProofPoints::from_bellman::<Bn128Field>(&proof);

    let proof = Proof::<ProofPoints> {
        proof: proof_points,
        inputs: inputs
            .iter()
            .map(|bn128| bn128.to_biguint().to_str_radix(16))
            .collect(),
        raw: hex::encode(&raw),
    };

    let ans = <G16 as ProofSystem<Bn128Field>>::verify(vk, proof);
    if ans {
        Ok(())
    } else {
        Err(String::from("no"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Private, ProofQrCode, PublicQr, QrRequest, Relation};
    use std::str::FromStr;
    use zokrates_field::Bn128Field;

    fn bn128(s: &str) -> Bn128Field {
        Bn128Field::try_from_dec_str(s).unwrap()
    }

    #[test]
    fn mimc7r10() {
        // values from ZoKrartes test

        assert_eq!(
            compute_mimc7r10_hash(&bn128("0"), &bn128("0")),
            bn128("6004544488495356385698286530147974336054653445122716140990101827963729149289")
        );
        assert_eq!(
            compute_mimc7r10_hash(&bn128("100"), &bn128("0")),
            bn128("2977550761518141183167168643824354554080911485709001361112529600968315693145")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128("100"),
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                )
            ),
            bn128("2977550761518141183167168643824354554080911485709001361112529600968315693145")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495618"
                ),
                &bn128("1")
            ),
            bn128("11476724043755138071320043459606423473319855817296339514744600646762741571430")
        );
        assert_eq!(
            compute_mimc7r10_hash(
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                ),
                &bn128(
                    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                )
            ),
            bn128("6004544488495356385698286530147974336054653445122716140990101827963729149289")
        );
    }

    #[test]
    fn generate_prover_key() {
        let m1 =
            bn128("10046037004840239707202533642544953578314335199439499999912878067091298310375");
        assert_eq!(compute_mimc7r10_hash(&bn128("10000"), &bn128("12")), m1);

        let private = Private {
            birthday: 2001,
            nonce: bn128("7999").into_byte_vector(),
        };
        let photo_hash = bn128("3").into_byte_vector();
        let contract = bn128("4").into_byte_vector();
        let key = super::generate_prover_key(private, photo_hash, contract);
        assert_eq!(32, key.len());

        assert_eq!(Bn128Field::from_byte_vector(key), m1);
    }

    fn test_verification(today: i32, birthday: i32, relation: Relation, delta: i32, result: bool) {
        let m1 =
            bn128("10046037004840239707202533642544953578314335199439499999912878067091298310375");
        assert_eq!(compute_mimc7r10_hash(&bn128("10000"), &bn128("12")), m1);

        let chain = PublicChain {
            photo_hash: bn128("3").into_byte_vector(),
            prover_key: m1.into_byte_vector(),
        };

        let rq = QrRequest {
            qr: PublicQr {
                today,
                relation,
                delta,
                contract: bn128("4").into_byte_vector(),
            },
            chain: chain.clone(),
            private: Private {
                birthday,
                nonce: bn128("7999").into_byte_vector(),
            },
        };

        let p = super::generate_proof(rq).unwrap();
        assert_eq!(result, super::verify_proof(&p, &chain).is_ok());
        let pp = ProofQrCode::from_str(&p.to_string()).unwrap();
        assert_eq!(result, super::verify_proof(&pp, &chain).is_ok());
    }

    #[test]
    fn verify_older() {
        test_verification(2020, 2001, Relation::Older, 18, true);
    }

    #[test]
    fn verify_younger() {
        test_verification(2020, 2001, Relation::Younger, 21, true);
    }

    #[test]
    fn verify_invalid() {
        test_verification(2020, 2010, Relation::Older, 18, false);
    }

    #[test]
    fn verify_marginal_case_older() {
        // Equality is refused. Wait till midnight.
        test_verification(2020, 2000, Relation::Older, 20, false);
    }

    #[test]
    fn verify_marginal_case_younger() {
        test_verification(2020, 2000, Relation::Older, 20, false);
    }
}
