use std::fmt::format;

use libaes::Cipher;
use scrypt::{scrypt, Params, Scrypt};
use serde::{Deserialize, Serialize};
use serde_json;

use password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

pub fn generate_hash_and_verify(passwordstring: String) -> String  {
    let password = passwordstring.as_bytes();
    let salt = SaltString::generate(&mut OsRng); 
    println!("salt: {}", salt);
    let password_hash = Scrypt.hash_password(password, &salt).unwrap().to_string();
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Scrypt.verify_password(password, &parsed_hash).is_ok());
    let salt_string = format!("{}", salt); // Store the salt in local storage.
    salt_string
    
}

pub fn already_used_salt(passwordstring: String, salt_string: String) -> String {
    let salt_str: &str = &salt_string[..];
    let salt = SaltString::new(salt_str).unwrap();
    let password = passwordstring.as_bytes();

    let password_hash = Scrypt.hash_password(password, &salt).unwrap().to_string();
    let parsed_hash = PasswordHash::new(&password_hash).unwrap();
    assert!(Scrypt.verify_password(password, &parsed_hash).is_ok());
    password_hash
}

pub fn encrypt_seed(password_hash: String, seed: String) -> (Vec<u8>, String) {
    let iv_salt = SaltString::generate(&mut OsRng);
    let iv_salt_string = format!("{}", iv_salt); 
    let iv_salt_string_clone = iv_salt_string.clone(); // Store iv salt in local storage
    let iv_salt_bytes = iv_salt_string.into_bytes();
    // println!("iv_salt_bytes len: {}", iv_salt_bytes.len());
    // println!("iv_salt_bytes: {:?}", iv_salt_bytes);
    let iv: &[u8; 16] = &iv_salt_bytes[0..16].try_into().unwrap();
    // println!("iv: {:?}", iv);
    let my_key_bytes = password_hash.into_bytes();
    // println!("my_key_bytes: {:?}", my_key_bytes);
    let my_key: &[u8; 16] = &my_key_bytes[0..16].try_into().unwrap();
    // println!("my_key_bytes: {:?}", my_key);

    let cipher = Cipher::new_128(my_key);

    // Encryption
    let encrypted = cipher.cbc_encrypt(iv, seed.as_bytes()); // Store in local storate
    // println!("{:?}", encrypted); 

    // Decryption
    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    let seed = String::from_utf8(decrypted).unwrap();
    // println!("{}", seed);
    (encrypted, iv_salt_string_clone)

}

pub fn decrypt_seed(password: String, seed: String) {
     
    let salt_str = generate_hash_and_verify(password.clone());
    let password_hash = already_used_salt(password, salt_str);
    let (encrypted, iv_salt_string) = encrypt_seed(password_hash.clone(), seed);
    let iv_salt_bytes = iv_salt_string.into_bytes();
    let iv: &[u8; 16] = &iv_salt_bytes[0..16].try_into().unwrap();
    let my_key_bytes = password_hash.into_bytes();
    let my_key: &[u8; 16] = &my_key_bytes[0..16].try_into().unwrap();
    let cipher = Cipher::new_128(my_key);
    let decrypted = cipher.cbc_decrypt(iv, &encrypted[..]);
    let seed = String::from_utf8(decrypted).unwrap();
    println!("{}", seed);


}
fn main() {
    // let password_hash = already_used_salt("hunter42".to_string());
    // println!("{}", password_hash);
    // let split: Vec<&str> = password_hash.split("$").collect();
    // let hash: String = split[split.len() - 1].to_string();
    // println!("hash {}", hash);
    let seed = "caution juice atom organ advance problem want pledge someone senior holiday very"
        .to_owned();
    decrypt_seed("passwordubiqutous".to_string(), seed)
    
    // let encrypted_vec = encrypt_seed(hash, seed);
    // let encrypted_string = "[23, 66, 241, 36, 221, 65, 170, 127, 61, 133, 210, 95, 26, 255, 3, 148, 249, 251, 33, 195, 96, 2, 51, 177, 139, 114, 96, 11, 252, 188, 196, 27, 170, 34, 52, 18, 130, 191, 204, 73, 234, 168, 210, 128, 144, 254, 142, 177, 209, 109, 157, 0, 107, 109, 190, 117, 243, 128, 114, 157, 70, 182, 20, 92, 147, 171, 102, 241, 119, 161, 157, 87, 106, 248, 232, 107, 23, 246, 150, 116, 223, 219, 10, 185, 137, 217, 79, 169, 57, 61, 69, 217, 133, 59, 202, 113]";
    // let mykey: Vec<u8> = serde_json::from_str(&encrypted_string).unwrap();
    // println!("{:?}", mykey)

}
