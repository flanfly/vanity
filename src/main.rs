use bip32::{Language, Mnemonic, XPrv, DerivationPath};
use std::str::FromStr;
use libsecp256k1::{PublicKey, SecretKey};
use sha3::{Digest, Keccak256};
use hex;
use rand::{SeedableRng, Rng, rngs::StdRng};
use std::{process, thread};

fn main() {
    let path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();

    let count = thread::available_parallelism().unwrap().get();
    let mut threads = Vec::with_capacity(count);

    println!("starting {} threads", count);
    
    for _ in 0..count {
        let path = path.clone();
        threads.push(thread::spawn(move || {
            let mut rand = [0u8; 32];
            let mut rng = StdRng::from_entropy();

            loop {
                rng.fill(&mut rand);

                let mne = Mnemonic::from_entropy(rand, Language::English);
                let xprv = XPrv::derive_from_path(mne.to_seed(""), &path).unwrap();
                let sec = SecretKey::parse_slice(&xprv.to_bytes()).unwrap();
                let publ = PublicKey::from_secret_key(&sec).serialize();
                let addr = Keccak256::digest(&publ[1..]);
                let addr = &addr[12..];

                if addr[0] == 0xde && addr[1] == 0xad && addr[addr.len() - 2] == 0xbe && addr[addr.len() - 1] == 0xef {
                    println!("address: 0x{}", hex::encode(addr));
                    println!("phrase: {}", mne.phrase());
                    process::exit(0);
                }
            }
        }));
    }

    for t in threads {
        t.join().unwrap();
    }
}
