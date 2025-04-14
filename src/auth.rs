use std::io::{self, Write};

use base64::Engine;
use srp6::{HostAPI, Srp6_4096, UserSecrets};
use srp6::prelude::BigNumber;

fn main() {
    println!("---------------------");
    println!("SERVER-SIDE KNOWLEDGE");
    println!("---------------------");
    print!("sign-on knowledge: registered username > ");
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
    
    let common_user_secrets = UserSecrets {
        username: common_user,
        salt: BigNumber::from_vec(&common_s),
        verifier: BigNumber::from_vec(&common_v),
    };
    
    println!();
//    println!("user: {}", common_user_secrets.username);
//    println!("s (salt): {}", common_user_secrets.salt);
//    println!("v (password verifier): {}", common_user_secrets.verifier);
//    println!();

    
    println!("auth: starting handshake ...");
    let srp6 = Srp6_4096::default();
    let (handshake, proof_verifier) = srp6.start_handshake(&common_user_secrets);
    
//    println!("Ks (private key of server): {}", proof_verifier.server_keys.1);
//    println!("B (public key of server): {}", handshake.B);
//    println!();

    println!("auth: handshake secrets, this value is for further proof step, IT IS NOT VISIBLE TO CLIENT");
    println!("Ks (private key of server): {}", gp_base64.encode(proof_verifier.server_keys.1.to_vec()));
    println!();
    println!("auth: handshake values for client, use these values for making proof");
    println!("B (public key of server): {}", gp_base64.encode(handshake.B.to_vec()));
    println!("s (user salt from server): {}", gp_base64.encode(handshake.s.to_vec()));
    println!();
    
}
