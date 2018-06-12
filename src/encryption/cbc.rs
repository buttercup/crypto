use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::Aes256;
use base64;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeIv, Cbc};
use hex;
use hmac::{Hmac, Mac};
use rand::{thread_rng, Rng};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type AesCbc = Cbc<Aes256, Pkcs7>;

pub const AES256_BLOCK_LEN: usize = 16;

pub enum AesCbcEncryptionError {
    HmacVerificationFailed,
    InvalidEncryptionKeyOrIv,
    InvalidBase64,
}

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
) -> Result<String, AesCbcEncryptionError> {
    // Encrypt the input using AES 256 CBC
    let iv = generate_iv();
    let iv_arr = GenericArray::clone_from_slice(&iv);

    let mut data_buffer = data.to_vec();
    let msg_len = data_buffer.len();
    data_buffer.extend_from_slice(&[0u8; AES256_BLOCK_LEN]);

    let cipher = match AesCbc::new_varkey(key, &iv_arr) {
        Ok(cipher) => cipher,
        Err(_) => return Err(AesCbcEncryptionError::InvalidEncryptionKeyOrIv),
    };
    let final_result = cipher
        .encrypt_pad(&mut data_buffer, msg_len)
        .expect("Trying to encrypt the content.");

    // Create an HMAC using SHA256
    let base64_result = base64::encode(&final_result);
    let mut hmac = HmacSha256::new_varkey(hmac_key).expect("HMAC can take key of any size.");

    hmac.input(base64_result.as_bytes());
    hmac.input(&iv);
    hmac.input(salt);

    let hmac_result = hmac.result();
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
    hmac_expected: &[u8],
) -> Result<Vec<u8>, AesCbcEncryptionError> {
    // Challenge hmac
    let mut hmac = HmacSha256::new_varkey(hmac_key).expect("HMAC can take key of any size.");

    hmac.input(encrypted_str.as_bytes());
    hmac.input(&iv);
    hmac.input(salt);

    let hmac_reproduced = hmac.result();

    // Compare using a time-sensitive method
    if !hmac_reproduced.is_equal(hmac_expected) {
        // Todo: fix error
        return Err(AesCbcEncryptionError::HmacVerificationFailed);
    }

    // Decrypt the input using AES 256 CBC
    let mut encrypted_data = base64::decode(&encrypted_str).ok().unwrap();
    let iv_arr = GenericArray::clone_from_slice(&iv);
    let cipher = match AesCbc::new_varkey(key, &iv_arr) {
        Ok(cipher) => cipher,
        Err(_) => return Err(AesCbcEncryptionError::InvalidEncryptionKeyOrIv),
    };
    let final_result = cipher
        .decrypt_pad(&mut encrypted_data)
        .expect("Trying to decrypt the content.");

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
