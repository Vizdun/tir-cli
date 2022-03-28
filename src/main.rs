use chrono::Local;
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
use serde::Serialize;

use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    command: Sub,
}

#[derive(Serialize)]
struct CreatePost {
    title: String,
    body: String,
    timestamp: i64,
    signature: String,
}

#[derive(Serialize)]
struct DeletePost {
    id: i32,
    timestamp: i64,
    signature: String,
}

#[derive(Subcommand)]
enum Sub {
    Create {
        url: String,
        privkey: String,
        title: String,
        file: String,
    },
    Delete {
        url: String,
        privkey: String,
        id: i32,
    },
}

fn sign(data: &[u8], file: String) -> String {
    let keypair = Rsa::private_key_from_pem(&std::fs::read(file).unwrap()).unwrap();
    let keypair = PKey::from_rsa(keypair).unwrap();

    let mut signer = Signer::new(MessageDigest::sha256(), &keypair).unwrap();
    signer.update(&data).unwrap();

    base64::encode(signer.sign_to_vec().unwrap())
}

fn main() {
    let args = Args::parse();

    match args.command {
        Sub::Create {
            url,
            privkey,
            title,
            file,
        } => {
            let body = std::fs::read_to_string(file).unwrap();
            let timestamp = Local::now().timestamp();
            let data = [title.as_bytes(), body.as_bytes(), &timestamp.to_le_bytes()].concat();

            let post = CreatePost {
                title,
                body,
                timestamp,
                signature: sign(&data, privkey),
            };

            let _resp = reqwest::blocking::Client::new()
                .post(format!("http://{}/create", url))
                .body(serde_json::to_string(&post).unwrap())
                .send()
                .unwrap();
        }
        Sub::Delete { url, privkey, id } => {
            let timestamp = Local::now().timestamp();
            let data = [&id.to_le_bytes()[..], &timestamp.to_le_bytes()[..]].concat();

            let post = DeletePost {
                id,
                timestamp,
                signature: sign(&data, privkey),
            };

            let _resp = reqwest::blocking::Client::new()
                .post(format!("http://{}/delete", url))
                .body(serde_json::to_string(&post).unwrap())
                .send()
                .unwrap();
        }
    }
}
