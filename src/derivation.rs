use hmac::Hmac;
use pbkdf2;
use sha2::Sha256;

pub fn pbkdf2(password: &str, salt: &str, iterations: usize, bits: usize) -> Vec<u8> {
    let mut to_store = Vec::new();
    to_store.resize(bits / 8, 0);

    pbkdf2::pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt.as_bytes(),
        iterations,
        &mut to_store,
    );

    to_store
}

#[test]
fn pbkdf2_test() {
    use hex;

    let buf = pbkdf2("password", "salt", 500, 512);
    assert_eq!(hex::encode(&buf), "d64e8195b42b448b3b11993fe808dba4ab8b27ee81e672ee8977bc7416e258a3f2b184eea77cf328c4f94dc17161fdb4c0e6e99400d5e83dad51dcefff911ae4");
}
