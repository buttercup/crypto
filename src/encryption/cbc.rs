use crypto::aes;
use crypto::blockmodes;
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::symmetriccipher::SymmetricCipherError;
use rand::{thread_rng, Rng};

pub fn encrypt(
    data: &[u8],
    key: &[u8],
    salt: &[u8],
    hmacKey: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    // Create a random IV
    let mut iv: [u8; 16] = [0; 16];
    thread_rng().fill(&mut iv[..]);

    println!("{:?}", iv);

    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, &iv, blockmodes::PkcsPadding);

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

    Ok(final_result)
}

pub fn decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

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
    let decrypted = decrypt(encrypted.as_slice(), key, iv).ok().unwrap();

    assert_eq!(decrypted.as_slice(), message);
}
