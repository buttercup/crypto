extern crate rust_crypto_wasm;

use rust_crypto_wasm::pbkdf2::{pbkdf2 as pbkdf2_core};
use rust_crypto_wasm::hmac::Hmac;
use rust_crypto_wasm::sha2::Sha256;

pub fn pbkdf2(password: &str, salt: &str, iterations: u32, bits: usize) -> Vec<u8> {
    let mut to_store = Vec::new();
    let mut mac = Hmac::new(Sha256::new(), password.as_bytes());

    to_store.resize(bits / 8, 0);
    pbkdf2_core(&mut mac, salt.as_bytes(), iterations, &mut to_store);
    to_store
}

#[test]
fn it_works() {
    let buf = pbkdf2("password", "salt", 500, 512);
    assert_eq!(buf.len(), 64);
    assert!(buf[0] > 0);
    assert!(buf[63] > 0);
}
