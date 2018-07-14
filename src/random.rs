use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

pub fn generate_bytes(length: usize) -> Vec<u8> {
    let mut dest = Vec::new();
    dest.resize(length, 0);
    thread_rng().fill(dest.as_mut_slice());
    dest
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
    let iv16 = generate_bytes(16);
    let iv32 = generate_bytes(32);

    assert_eq!(iv16.len(), 16);
    assert_eq!(iv32.len(), 32);
}

#[test]
fn random_string_test() {
    let random_string = generate_string(20);
    assert_eq!(random_string.len(), 20);
}
