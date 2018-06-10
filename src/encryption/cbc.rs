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

pub fn encrypt(
    data: &[u8],
    key: &[u8],
    salt: &[u8],
    hmac_key: &[u8],
) -> Result<String, SymmetricCipherError> {
    // Create a random IV
    let mut iv: [u8; 16] = [0; 16];
    thread_rng().fill(&mut iv[..]);

    // Encrypt the input using AES 256 CBC
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
) -> Result<Vec<u8>, SymmetricCipherError> {
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

    Ok(final_result)
}

#[test]
fn cbc_test() {
    let message = "Hello World!".as_bytes();
    let key = "-3MWk7o_RLT32ZF30rIhHUQqh_gB8V4G".as_bytes();
    let iv = "hv3DdMH0-RQLu1Sx".as_bytes();

    let encrypted = encrypt(message, key, iv, iv).ok().unwrap();
    println!("{:?}", encrypted);
    // let decrypted = decrypt(encrypted.as_slice(), key, iv).ok().unwrap();

    // assert_eq!(decrypted.as_slice(), message);
}
