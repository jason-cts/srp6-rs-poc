use std::io::{self, Write};

use base64::Engine;
use srp6::{prelude::BigNumber, StrongProofVerifier};

fn main() {
    let gp_base64 = base64::engine::general_purpose::STANDARD;
    
    println!("---------------------");
    println!("CLIENT-SIDE KNOWLEDGE");
    println!("---------------------");
    
    print!("client-proof-gen-knowledge: K (strong-proof verifier) > ");
    io::stdout().flush().unwrap();
    let mut proof_k = String::new();
    std::io::stdin().read_line(&mut proof_k).unwrap();
    proof_k = proof_k.trim().to_owned();
    let proof_k = gp_base64.decode(proof_k).expect("invalid base64 format of A!");

    print!("client-proof-gen-knowledge: A (client public key) > ");
    io::stdout().flush().unwrap();
    let mut proof_a = String::new();
    std::io::stdin().read_line(&mut proof_a).unwrap();
    proof_a = proof_a.trim().to_owned();
    let proof_a = gp_base64.decode(proof_a).expect("invalid base64 format of A!");

    print!("client-proof-gen-knowledge: M1 (client proof) > ");
    io::stdout().flush().unwrap();
    let mut proof_m1 = String::new();
    std::io::stdin().read_line(&mut proof_m1).unwrap();
    proof_m1 = proof_m1.trim().to_owned();
    let proof_m1 = gp_base64.decode(proof_m1).expect("invalid base64 format of M1!");

    let strong_proof_verifier: StrongProofVerifier<512> = StrongProofVerifier {
        A: BigNumber::from_vec(&proof_a),
        K: BigNumber::from_vec(&proof_k), 
        M1: BigNumber::from_vec(&proof_m1)
    };

    println!("---------------------------");
    println!("PARAMETERS FROM SERVER-SIDE");
    println!("---------------------------");
    
    print!("auth-proof-knowledge: M2 (strong-proof from server) > ");
    io::stdout().flush().unwrap();
    let mut proof_m2 = String::new();
    std::io::stdin().read_line(&mut proof_m2).unwrap();
    proof_m2 = proof_m2.trim().to_owned();
    let proof_m2 = gp_base64.decode(proof_m2).expect("invalid base64 format of M1!");
    println!();

    let session_key_client = match strong_proof_verifier.verify_strong_proof(&BigNumber::from_vec(&proof_m2)) {
        Ok(k) => k,
        Err(e) => {
            println!("client-strong-proof: strong_proof FAILED!, e: {}", e);
            return;
        },
    };
    println!("client-strong-proof: PASS!");
    println!("client-strong-proof: session_key: {}", gp_base64.encode(&session_key_client.to_vec()));
    println!();
    
}
