use std::io::{self, stdin, Write};

use srp6::{ClearTextPasswordRef, HostAPI, Srp6_4096, UserSecrets, UsernameRef};

fn main() {
    print!("client: input register username > ");
    io::stdout().flush().unwrap();
    let mut input_user = String::new();
    std::io::stdin().read_line(&mut input_user).unwrap();
    input_user = input_user.trim().to_owned();
    let user: UsernameRef = input_user.as_str();
    
    print!("client: input register plaintext password > ");
    io::stdout().flush().unwrap();
    let mut input_password = String::new();
    std::io::stdin().read_line(&mut input_password).unwrap();
    input_password = input_password.trim().to_owned();
    let password: ClearTextPasswordRef = input_password.as_str();
//    
    let srp = Srp6_4096::default();
    println!("common knowledge:");
    println!("N: {}", srp.N);
    println!("g: {}", srp.g);
    println!("k: {}", srp.k);
    println!();
    
    let (salt_s, verifier_v) = srp.generate_new_user_secrets(user, password);
    let secrets = UserSecrets {
        username: user.to_owned(),
        salt: salt_s,
        verifier: verifier_v,
    };
    println!("client: --> server");
    println!("server: user: {}", user);
    println!("server: salt: {}", secrets.salt);
    println!("server: password verifier: {}", secrets.verifier);
    println!("server: stored.");
    println!();
    
    loop {
        print!("press enter to start authentication ...");
        io::stdout().flush().unwrap();
        let mut dummy = String::new();
        stdin().read_line(&mut dummy).unwrap();
        
        print!("client: input challenge user > ");
        io::stdout().flush().unwrap();
        let mut input_cuser = String::new();
        std::io::stdin().read_line(&mut input_cuser).unwrap();
        input_cuser = input_cuser.trim().to_owned();
        let challenge_user: UsernameRef = &input_cuser;
        println!("client: --> server");
        println!("server: challenge user: '{}'", &challenge_user);
        if challenge_user != secrets.username {
            println!("username not found!");
            continue;
        }
        
        println!("server: starting handshake ...");
        let (handshake, proof_verifier) = Srp6_4096::default().start_handshake(&secrets);
        
        println!("server: handshake secrets:");
        println!("server: private key: {}", proof_verifier.server_keys.1);
        println!();
        println!("server: handshake --> client");
        println!("client: handshake B (public key): {}", handshake.B);
        println!("client: handshake N (prime): {}", handshake.N);
        println!("client: handshake g (generator modulo): {}", handshake.g);
        println!("client: handshake k (multiplier): {}", handshake.k);
        println!("client: handshake s (salt): {}", handshake.s);
        println!();
        
        print!("client: input challenge plaintext password > ");
        io::stdout().flush().unwrap();
        let mut input_cpassword = String::new();
        std::io::stdin().read_line(&mut input_cpassword).unwrap();
        input_cpassword = input_cpassword.trim().to_owned();
        let challenge_password: ClearTextPasswordRef = &input_cpassword;
        println!("client: challenge user: '{}'", &challenge_user);
        println!("client: challenge password: '{}'", &challenge_password);
        
        // client calculate challenge passphrase into proof, and send proof to server
        println!("client: calculating proof ...");
        let (proof, strong_proof_verifier) =
            handshake.calculate_proof(challenge_user, challenge_password).unwrap();
        println!("client: --> server");
        println!("server: challenge user: {}", &challenge_user);
        println!("server: proof M1: {}", proof.M1);
        println!("server: proof public key: {}", proof.A);
        println!();
        
        // server verifies the proof
        println!("server: proof verifing ...");
        let (strong_proof, session_key_server) = match proof_verifier.verify_proof(&proof) {
            Ok((p, k)) => (p, k),
            Err(e) => {
                println!("server: proof FAILED!, e: {}", e);
                continue;
            },
        };
        println!("server: PASS!");
        println!("server: session_key: {}", session_key_server);
        println!("server: --> client");
        println!("client: strong proof: {}", strong_proof);
        println!("client: verifing strong proof ...");
        let session_key_client = match strong_proof_verifier.verify_strong_proof(&strong_proof) {
            Ok(k) => k,
            Err(e) => {
                println!("client: strong_proof FAILED!, e: {}", e);
                continue;
            },
        };
        println!("client: PASS!");
        println!("client: session_key: {}", session_key_client);
        println!();
    }
    
}
