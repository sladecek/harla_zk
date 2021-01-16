/// Command line utility to simulate a 'LegalAge' prover.
use chrono::{Datelike, Local, NaiveDate};
use clap::{App, Arg};
use harla_zk::api::{
    age_to_delta, naive_date_to_jd, Private, PublicChain, PublicQr, QrRequest, Relation,
};
use harla_zk::zk::{generate_proof, generate_prover_key};
use image::Luma;
use qrcode::QrCode;
use serde::{Deserialize, Serialize};
use serde_json;
use std::fs;
use zokrates_field::{Bn128Field, Field};

#[derive(Debug, PartialEq, Clone)]
struct Parameters {
    pub prover_db: String,
    pub today: i32,
    pub relation: Relation,
    pub age: i32,
    pub proof: String,
    pub qr: String,
}

fn main() {
    let p = parse_arguments();
    let pdb: ProverDb = serde_json::from_str(&fs::read_to_string(&p.prover_db).unwrap()).unwrap();
    let nonce = Bn128Field::try_from_dec_str(&pdb.nonce)
        .expect("cannot decode 'nonce' in the proverDb file")
        .into_byte_vector();
    let contract = Bn128Field::try_from_dec_str(&pdb.contract)
        .expect("cannot decode 'contract' in the proverDb file")
        .into_byte_vector();
    let photo_hash = Bn128Field::try_from_dec_str(&pdb.photo_hash)
        .expect("cannot decode 'photo_hash' in the proverDb file")
        .into_byte_vector();

    let delta = age_to_delta(pdb.birthday, p.age, p.relation);
    let private = Private {
        birthday: pdb.birthday,
        nonce: nonce,
    };
    let prover_key = generate_prover_key(&private.clone(), &contract, &photo_hash);

    let rq = QrRequest {
        qr: PublicQr {
            today: p.today,
            contract: contract,
            delta,
            relation: p.relation,
        },
        chain: PublicChain {
            photo_hash: photo_hash,
            prover_key,
        },
        private,
    };
    let proof = generate_proof(rq).unwrap();
    let ps = proof.to_string();
    let qrf = QrFile { qr: ps.clone() };
    //    let json: String = serde_json::to_string(&qrf).unwrap();
    fs::write(p.proof, ps).unwrap();
    //    fs::write(p.proof, json).unwrap();

    let code = QrCode::new(qrf.qr).unwrap();
    let image = code.render::<Luma<u8>>().build();
    image.save(p.qr).unwrap();
    let string = code
        .render()
        .light_color('\u{2b1c}')
        .dark_color('\u{2b1b}')
        .build();
    println!("{}", string);
}

fn parse_arguments() -> Parameters {
    let matches = App::new("prove")
        .version("0.1")
        .author("Ladislav Sladecek <ladislav.sladecek@gmail.com>")
        .about("Command line utility to simulate a 'LegalAge' prover.")
        .arg(
            Arg::with_name("older")
                .long("older")
                .value_name("YEARS")
                .help("Generates the proof that the user is older than YEARS.")
                .conflicts_with("younger")
                .required_unless("younger")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("younger")
                .long("younger")
                .value_name("YEARS")
                .help("Generates the proof that the user is younger than YEARS.")
                .conflicts_with("older")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("today")
                .long("today")
                .value_name("YYYY-MM-DD")
                .help("Defines current date.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("prover-db")
                .long("prover-db")
                .value_name("FILE")
                .help("Defines input .json file containing prover's secrets.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("proof")
                .long("proof")
                .value_name("FILE")
                .help("Defines output .json file for the generated proof.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("qr")
                .long("qr")
                .value_name("FILE")
                .help("Defines output file for the QR code.")
                .takes_value(true),
        )
        .get_matches();

    let mut relation = Relation::Older;
    let today = naive_date_today();
    let age = if matches.is_present("older") {
        matches.value_of("older").unwrap()
    } else {
        relation = Relation::Younger;
        matches.value_of("younger").unwrap()
    }
    .parse::<i32>()
    .unwrap();

    let p = Parameters {
        age,
        relation,
        today: naive_date_to_jd(today),
        prover_db: String::from(matches.value_of("prover-db").unwrap_or("prover-db.json")),
        proof: String::from(matches.value_of("proof").unwrap_or("proof.json")),
        qr: String::from(matches.value_of("qr").unwrap_or("proof-qr.jpg")),
    };

    p
}

#[derive(Deserialize, Debug)]
struct ProverDb {
    pub birthday: i32,
    pub nonce: String,
    pub contract: String,
    pub photo_hash: String,
}

#[derive(Serialize, Debug)]
struct QrFile {
    pub qr: String,
}

fn naive_date_today() -> NaiveDate {
    let l = Local::now();
    NaiveDate::from_ymd(l.year(), l.month(), l.day())
}
