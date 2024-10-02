use oqs::*;
use hex;
use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use block_padding::{Pkcs7, UnpadError};
use rand::Rng;
use aes::cipher::{BlockSizeUser, KeyIvInit, BlockEncryptMut, BlockDecryptMut};

// Custom error type
#[derive(Debug)]
enum AppError {
    OqsError(oqs::Error),
    EncryptionError(cbc::cipher::inout::PadError),
    DecryptionError(UnpadError),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::OqsError(e) => write!(f, "OQS error: {:?}", e),
            AppError::EncryptionError(e) => write!(f, "Encryption error: {:?}", e),
            AppError::DecryptionError(e) => write!(f, "Decryption error: {:?}", e),
        }
    }
}

impl std::error::Error for AppError {}

fn main() -> std::result::Result<(), AppError> {
    // Initialize OQS signature and KEM algorithms
    let sigalg = sig::Sig::new(sig::Algorithm::Dilithium2).map_err(AppError::OqsError)?;
    let kemalg = kem::Kem::new(kem::Algorithm::Kyber512).map_err(AppError::OqsError)?;

    // Generate key pairs for A
    let (a_sig_pk, a_sig_sk) = sigalg.keypair().map_err(AppError::OqsError)?;
    println!("A's signature key pair generated.");

    // Generate key pairs for B
    let (b_sig_pk, b_sig_sk) = sigalg.keypair().map_err(AppError::OqsError)?;
    println!("B's signature key pair generated.");

    // A generates KEM key pair
    let (kem_pk, kem_sk) = kemalg.keypair().map_err(AppError::OqsError)?;
    println!("A generated KEM key pair.");

    // A signs the KEM public key
    let signature = sigalg.sign(kem_pk.as_ref(), &a_sig_sk).map_err(AppError::OqsError)?;
    println!("A signed the KEM public key.");

    // A sends KEM public key and signature to B
    println!("A sent KEM public key and signature to B.");

    // B verifies A's signature
    sigalg.verify(kem_pk.as_ref(), &signature, &a_sig_pk).map_err(AppError::OqsError)?;
    println!("B verified A's signature.");

    // B encapsulates to generate a shared secret and a ciphertext
    let (kem_ct, b_kem_ss) = kemalg.encapsulate(&kem_pk).map_err(AppError::OqsError)?;
    println!("B encapsulated to generate a shared secret and ciphertext.");

    // B signs the ciphertext
    let signature = sigalg.sign(kem_ct.as_ref(), &b_sig_sk).map_err(AppError::OqsError)?;
    println!("B signed the ciphertext.");

    // B sends ciphertext and signature to A
    println!("B sent ciphertext and signature to A.");

    // A verifies B's signature
    sigalg.verify(kem_ct.as_ref(), &signature, &b_sig_pk).map_err(AppError::OqsError)?;
    println!("A verified B's signature.");

    // A decapsulates to get the shared secret
    let a_kem_ss = kemalg.decapsulate(&kem_sk, &kem_ct).map_err(AppError::OqsError)?;
    println!("A decapsulated to get the shared secret.");

    // Ensure both parties share the same secret
    assert_eq!(a_kem_ss, b_kem_ss);
    println!("Key exchange successful. Both parties share the same secret.");

    // Print the shared secret in HEX
    println!("Shared secret (HEX): {}", hex::encode(&a_kem_ss));

    // Use the shared secret for AES encryption (using the first 32 bytes as the key)
    let key: [u8; 32] = a_kem_ss.as_ref()[..32].try_into().expect("Shared secret is too short");
    println!("AES key length: {} bytes", key.len());

    // Generate a random IV (Initialization Vector)
    let iv: [u8; 16] = rand::thread_rng().gen();
    println!("IV length: {} bytes", iv.len());

    // Example plaintext message
    let plaintext = b"The quick brown fox jumps over the lazy dog.";
    println!("Plaintext length: {} bytes", plaintext.len());

    // Encrypt the plaintext
    let ciphertext = encrypt(&key, &iv, plaintext)?;
    println!("Encryption successful");
    println!("Ciphertext (HEX): {}", hex::encode(&ciphertext));

    // Decrypt the ciphertext
    let decrypted = decrypt(&key, &iv, &ciphertext)?;
    println!("Decryption successful");
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));

    Ok(())
}

fn encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> std::result::Result<Vec<u8>, AppError> {
    let cipher = Encryptor::<Aes256>::new(key.into(), iv.into());
    let block_size = Aes256::block_size();
    let mut buffer = vec![0u8; plaintext.len() + block_size];
    buffer[..plaintext.len()].copy_from_slice(plaintext);
    println!("Buffer before padding: {:?}", buffer);
    let ciphertext_len = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .map_err(AppError::EncryptionError)?.len();
    buffer.truncate(ciphertext_len);
    println!("Buffer after padding: {:?}", buffer);
    Ok(buffer)
}

fn decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8]) -> std::result::Result<Vec<u8>, AppError> {
    let cipher = Decryptor::<Aes256>::new(key.into(), iv.into());
    let mut buffer = ciphertext.to_vec();
    println!("Buffer before unpadding: {:?}", buffer);
    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(AppError::DecryptionError)?;
    println!("Buffer after unpadding: {:?}", decrypted);
    Ok(decrypted.to_vec())
}