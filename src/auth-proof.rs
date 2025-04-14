use std::io::{self, Write};

use base64::Engine;
use srp6::{prelude::BigNumber, HandshakeProof, HandshakeProofVerifier, Srp6_4096, UserSecrets};

fn main() {
    println!("---------------------");
    println!("SERVER-SIDE KNOWLEDGE");
    println!("---------------------");
    print!("sign-on knowledge: register username > ");
    io::stdout().flush().unwrap();
    let mut common_user = String::new();
    std::io::stdin().read_line(&mut common_user).unwrap();
    common_user = common_user.trim().to_owned();

    let gp_base64 = base64::engine::general_purpose::STANDARD;

    print!("sign-on knowledge: Base64 s (salt) > ");
    io::stdout().flush().unwrap();
    let mut common_s_base64 = String::new();
    std::io::stdin().read_line(&mut common_s_base64).unwrap();
    common_s_base64 = common_s_base64.trim().to_owned();
    let common_s = gp_base64.decode(common_s_base64).expect("invalid base64 format of s!");

    print!("sign-on knowledge: Base64 v (verifier) > ");
    io::stdout().flush().unwrap();
    let mut common_v_base64 = String::new();
    std::io::stdin().read_line(&mut common_v_base64).unwrap();
    common_v_base64 = common_v_base64.trim().to_owned();
    let common_v = gp_base64.decode(common_v_base64).expect("invalid base64 format of v!");

    print!("auth-knowledge: Ks (private key of server) > ");
    io::stdout().flush().unwrap();
    let mut input_private_ks = String::new();
    std::io::stdin().read_line(&mut input_private_ks).unwrap();
    input_private_ks = input_private_ks.trim().to_owned();
    let input_private_ks = gp_base64.decode(input_private_ks).expect("invalid base64 format of server private key!");
    
    print!("auth-knowledge: B (public key of server) > ");
    io::stdout().flush().unwrap();
    let mut input_public_ks = String::new();
    std::io::stdin().read_line(&mut input_public_ks).unwrap();
    input_public_ks = input_public_ks.trim().to_owned();
    let input_public_ks = gp_base64.decode(input_public_ks).expect("invalid base64 format of server public key!");

    let common_user_secrets = UserSecrets {
        username: common_user,
        salt: BigNumber::from_vec(&common_s),
        verifier: BigNumber::from_vec(&common_v),
    };

    let srp = Srp6_4096::default();

    let proof_verifier = HandshakeProofVerifier {
        server_keys: (BigNumber::from_vec(&input_public_ks), BigNumber::from_vec(&input_private_ks)),
        user: common_user_secrets.to_owned(),
        g: srp.g,
        N: srp.N,
    };
    
    println!();
//    println!("user: {}", common_user_secrets.username);
//    println!("s (salt): {}", common_user_secrets.salt);
//    println!("v (password verifier): {}", common_user_secrets.verifier);
//    println!("Ks (private key of server): {}", proof_verifier.server_keys.1);
//    println!("B (public key of server): {}", proof_verifier.server_keys.0);
//    println!();

    println!("---------------------------");
    println!("PARAMETERS FROM CLIENT-SIDE");
    println!("---------------------------");
    
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
    
    let proof: HandshakeProof<512, 512> = HandshakeProof {
        A: BigNumber::from_vec(&proof_a),
        M1: BigNumber::from_vec(&proof_m1),
    };
    println!();
    
    // server verifies the proof
    println!("auth-proof: verifing client proof ...");
    let (strong_proof, session_key_server) = match proof_verifier.verify_proof(&proof) {
        Ok((p, k)) => (p, k),
        Err(e) => {
            println!("auth-proof: proof FAILED!, e: {}", e);
            return;
        },
    };
    println!("PASS!");
    println!("M2 (strong proof from server): {}", gp_base64.encode(&strong_proof.to_vec()));
    println!();
    println!("S (session_key) of server side: {}", gp_base64.encode(&session_key_server.to_vec()));
    println!();
}
