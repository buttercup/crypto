use crypto::aes::{cbc_decryptor, cbc_encryptor, KeySize};
use crypto::blockmodes;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::hmac::Hmac;
use crypto::mac::Mac;
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
    let mut hmac = Hmac::new(Sha256::new(), hmac_key);
    hmac.input(&final_result);
    hmac.input(&iv);
    hmac.input(salt);
    let hmac_result = hmac.result();
    let hmac_code = hmac_result.code();

    // Glue together the result
    // The encrypted content is Base64 everything else is Hex
    Ok(glued_result(vec![
        base64::encode(&final_result),
        hex::encode(hmac_code),
        hex::encode(&iv),
        hex::encode(salt),
    ]))
}

pub fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
    salt: &[u8],
    hmac_key: &[u8],
    hmac: &[u8],
) -> Result<String, SymmetricCipherError> {
    // Decrypt the input using AES 256 CBC
    let mut decryptor = cbc_decryptor(KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(encrypted_data);
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

    Ok(base64::encode(&final_result))
}

#[test]
fn cbc_encryption_test() {
    let message = "Hello World!".as_bytes();
    let key = "-3MWk7o_RLT32ZF30rIhHUQqh_gB8V4G".as_bytes();
    let salt = "apF3M5u3dNbYt45ok92WAGjz4U7FJYDV".as_bytes();
    let hmac_key = "_GV08*=cb1#y3aA;8Xw#bYhV-nfe#$x7".as_bytes();

    let encrypted = encrypt(message, key, salt, hmac_key).ok().unwrap();
    assert_eq!(encrypted.len(), 187);
}

#[test]
fn cbc_decryption_test() {
    let encrypted = base64::decode("8OaBXdNSiwz5T6ucJ1YEvQ==").ok().unwrap();
    let key = "-3MWk7o_RLT32ZF30rIhHUQqh_gB8V4G".as_bytes();
    let hmac_key = "_GV08*=cb1#y3aA;8Xw#bYhV-nfe#$x7".as_bytes();
    let salt = "apF3M5u3dNbYt45ok92WAGjz4U7FJYDV".as_bytes();
    let iv = hex::decode("05e320828ef2d1d0579ed5fb23c1b275")
        .ok()
        .unwrap();
    let hmac = hex::decode("8e41ad6b51f08f66b4f1e892801584568ae1f4248241acea101d05f7fa68cf1f")
        .ok()
        .unwrap();

    let decrypted = decrypt(
        encrypted.as_slice(),
        key,
        iv.as_slice(),
        salt,
        hmac_key,
        hmac.as_slice(),
    ).ok()
        .unwrap();
    assert_eq!(decrypted, base64::encode("Hello World!"));
}
