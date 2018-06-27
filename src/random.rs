use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn generate_iv() -> [u8; 16] {
    let mut iv: [u8; 16] = [0; 16];
    thread_rng().fill(&mut iv[..]);
    iv
}

pub fn generate_string(length: usize) -> String {
    let mut string = String::new();
    for char in thread_rng().sample_iter(&Alphanumeric).take(length) {
        string.push(char);
    }
    string
}

#[test]
fn random_iv_test() {
    let iv = generate_iv();
    assert_eq!(iv.len(), 16);
}

#[test]
fn random_string_test() {
    let random_string = generate_string(20);
    assert_eq!(random_string.len(), 20);
}
