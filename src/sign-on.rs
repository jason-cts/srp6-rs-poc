use std::io::{self, Write};

use base64::Engine;
use srp6::{ClearTextPasswordRef, HostAPI, Srp6_4096, UserSecrets, UsernameRef};

fn main() {
    print!("sign-on: input register username > ");
    io::stdout().flush().unwrap();
    let mut input_user = String::new();
    std::io::stdin().read_line(&mut input_user).unwrap();
    input_user = input_user.trim().to_owned();
    let user: UsernameRef = input_user.as_str();
    
    print!("sign-on: input register plaintext password > ");
    io::stdout().flush().unwrap();
    let mut input_password = String::new();
    std::io::stdin().read_line(&mut input_password).unwrap();
    input_password = input_password.trim().to_owned();
    let password: ClearTextPasswordRef = input_password.as_str();
//    
    let srp = Srp6_4096::default();
    
    let (salt_s, verifier_v) = srp.generate_new_user_secrets(user, password);
    let secrets = UserSecrets {
        username: user.to_owned(),
        salt: salt_s,
        verifier: verifier_v,
    };
    
    //
    println!("sign-on: {}", user);
    println!("s (salt): {}", secrets.salt);
    println!("v (password verifier): {}", secrets.verifier);
    println!();
    //
    
    let gp_base64 = base64::engine::general_purpose::STANDARD;
    println!("sign-on: {}", user);
    println!("s (salt): {}", gp_base64.encode(secrets.salt.to_vec()));
    println!("v (password verifier): {}", gp_base64.encode(secrets.verifier.to_vec()));
    println!("use these values for auth.");
}
