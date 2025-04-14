use std::io::{self, Write};

use base64::Engine;
use srp6::{prelude::BigNumber, ClearTextPasswordRef, Handshake, Srp6_4096, UsernameRef};

fn main() {
    let gp_base64 = base64::engine::general_purpose::STANDARD;
    println!("---------------------");
    println!("CLIENT-SIDE KNOWLEDGE");
    println!("---------------------");
    print!("sign-on knowledge: register username > ");
    io::stdout().flush().unwrap();
    let mut input_user = String::new();
    std::io::stdin().read_line(&mut input_user).unwrap();
    input_user = input_user.trim().to_owned();
    let user: UsernameRef = input_user.as_str();

    print!("auth-knowledge: B (public key from server) > ");
    io::stdout().flush().unwrap();
    let mut input_b = String::new();
    std::io::stdin().read_line(&mut input_b).unwrap();
    let input_b = gp_base64.decode(input_b.trim().to_owned()).expect("invalid B!");

    print!("auth-knowledge: s (user salt from server) > ");
    io::stdout().flush().unwrap();
    let mut input_s = String::new();
    std::io::stdin().read_line(&mut input_s).unwrap();
    let input_s = gp_base64.decode(input_s.trim().to_owned()).expect("invalid s!");

    let srp = Srp6_4096::default();
    println!();
    
    let handshake: Handshake<512, 512> = Handshake {
        N: srp.N,
        g: srp.g,
        k: srp.k,
        B: BigNumber::from_vec(&input_b),
        s: BigNumber::from_vec(&input_s),
    };
    
//    println!("B (public key of server): {}", handshake.B);
//    println!("s (user salt from server): {}", handshake.s);
    
    print!("client-proof-gen: challenge plaintext password > ");
    io::stdout().flush().unwrap();
    let mut input_password = String::new();
    std::io::stdin().read_line(&mut input_password).unwrap();
    input_password = input_password.trim().to_owned();
    let password: ClearTextPasswordRef = input_password.as_str();
     
    // client calculate challenge passphrase into proof, and send proof to server
    println!("client-proof-gen: calculating proof ...");
    let (proof, strong_proof_verifier) =
        handshake.calculate_proof(user, password).unwrap();
        
//    println!("A (client public key): {}", proof.A);
//    println!("M1 (client proof): {}", proof.M1);
//    println!("K (strong-proof verifier): {}", strong_proof_verifier.K);
//    println!();

    println!("A (client public key): {}", gp_base64.encode(&proof.A.to_vec()));
    println!("M1 (client proof): {}", gp_base64.encode(&proof.M1.to_vec()));
    println!();
    println!("use this value for further client step");
    println!("K (strong-proof verifier): {}", gp_base64.encode(&strong_proof_verifier.K.to_vec()));
    println!();
}
