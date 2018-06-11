use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha2::Sha256;
use crypto::symmetriccipher::SymmetricCipherError;

use base64;
use hex;
use rand::{thread_rng, Rng};

fn glued_result(string_list: Vec<String>) -> String {
    string_list.join("$")
}

fn generate_iv() -> [u8; 16] {
    let mut iv: [u8; 16] = [0; 16];
    thread_rng().fill(&mut iv[..]);
    iv
}

fn create_hmac(hmac_key: &[u8], data: &[u8], iv: &[u8], salt: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha256::new(), hmac_key);

    hmac.input(data);
    hmac.input(iv);
    hmac.input(salt);

    hmac.result()
}

pub fn encrypt(
    data: &[u8],
    key: &[u8],
    salt: &[u8],
    hmac_key: &[u8],
) -> Result<String, SymmetricCipherError> {
    // Encrypt the input using AES 256 CBC
    let iv = generate_iv();
    let mut encryptor = cbc_encryptor(KeySize::KeySize256, key, &iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    // Create an HMAC using SHA256
    let base64_result = base64::encode(&final_result);
    let hmac_result = create_hmac(hmac_key, &base64_result.as_bytes(), &iv, salt);
    let hmac_code = hmac_result.code();

    // Glue together the result
    // The encrypted content is Base64 everything else is Hex
    Ok(glued_result(vec![
        base64_result,
        hex::encode(hmac_code),
        hex::encode(&iv),
        hex::encode(salt),
    ]))
}

pub fn decrypt(
    encrypted_str: String,
    key: &[u8],
    iv: &[u8],
    salt: &[u8],
    hmac_key: &[u8],
    hmac: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    // Challenge hmac
    let hmac_reproduced = create_hmac(hmac_key, encrypted_str.as_bytes(), iv, salt);
    let hmac_expected = MacResult::new(hmac);

    // Compare using a time-sensitive method
    if !hmac_expected.eq(&hmac_reproduced) {
        // Todo: fix error
        return Err(SymmetricCipherError::InvalidLength);
    }

    // Decrypt the input using AES 256 CBC
    let encrypted_data = base64::decode(&encrypted_str).ok().unwrap();
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(encrypted_data.as_slice());
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result.to_vec())
}

#[test]
fn cbc_encryption_test() {
    let message = b"Hello World!";
    let key = b"-3MWk7o_RLT32ZF30rIhHUQqh_gB8V4G";
    let salt = b"apF3M5u3dNbYt45ok92WAGjz4U7FJYDV";
    let hmac_key = b"_GV08*=cb1#y3aA;8Xw#bYhV-nfe#$x7";

    let encrypted = encrypt(message, key, salt, hmac_key).ok().unwrap();
    assert_eq!(encrypted.len(), 187);
}

#[test]
fn cbc_decryption_test() {
    let encrypted = "BekSVRIFrwvG9Qx5iywbWg==".to_string();
    let key = b"-3MWk7o_RLT32ZF30rIhHUQqh_gB8V4G";
    let hmac_key = b"_GV08*=cb1#y3aA;8Xw#bYhV-nfe#$x7";
    let salt = b"apF3M5u3dNbYt45ok92WAGjz4U7FJYDV";
    let iv = hex::decode("f3c4bc3538d5ea1f91934cdee72a72d8")
        .ok()
        .unwrap();
    let hmac = hex::decode("7c8f31a3cc4a7c7f6de92da9b35ce1368657e13da535e4c0a9c038a408b86f92")
        .ok()
        .unwrap();

    let decrypted = decrypt(
        encrypted,
        key,
        iv.as_slice(),
        salt,
        hmac_key,
        hmac.as_slice(),
    ).ok()
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"Hello World!");
}
