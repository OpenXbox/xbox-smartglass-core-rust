extern crate rustc_serialize;
extern crate ring;
extern crate untrusted;
extern crate crypto;

use self::rustc_serialize::hex::FromHex;
use self::ring::{agreement, hmac, rand, digest};
use self::untrusted::Input;
use self::crypto::aes;
use self::crypto::aes::KeySize;
use self::crypto::blockmodes;
use self::crypto::buffer::{RefReadBuffer, RefWriteBuffer, WriteBuffer, ReadBuffer, BufferResult};

/// A class for adding salts to data before encryption
enum Salt {
    Prepend(Vec<u8>),
    Append(Vec<u8>)
}

impl Salt {
    /// Applies the salt to data and returns the salted data
    ///
    /// # Arguments
    /// * `data` - The data to be salted
    fn apply(&self, data: &Vec<u8>) -> Vec<u8> {
        match *self {
            Salt::Prepend(ref salt) => [&salt[..], &data[..]].concat(),
            Salt::Append(ref salt) => [&data[..], &salt[..]].concat()
        }
    }
}

/// The particular crypto ipmlementation used by SmartGlass
struct Crypto {
    salts: [Salt; 2],
    publicKey: Vec<u8>,
    aesKey: [u8;16],
    ivKey: [u8;16],
    hmacKey: [u8;32]
}

impl Crypto {
    /// Creates a new Crypto
    ///
    /// # Arguments
    /// * foreignPublicKey - The public key of the xbox one associated with the SG Session
    pub fn new(foreignPublicKey: &[u8]) -> Crypto {
        let rng = rand::SystemRandom::new();
        // TODO: error handling
        Crypto::from_rand(foreignPublicKey, rng)
    }

    fn from_rand<T>(foreignPublicKey: &[u8], rng: T) -> Crypto
        where T: rand::SecureRandom {
         // Safe to unwrap here because the string is static and known to be valid
        //  text. We should never recieve anthing but Ok(val)
        let prependSalt = Salt::Prepend("D637F1AAE2F0418C".from_hex().unwrap());
        let appendSalt = Salt::Append("A8F81A574E228AB7".from_hex().unwrap());
        let salts = [prependSalt, appendSalt];

        let untrustedForiegnKey = Input::from(foreignPublicKey);
        let privateKey = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let mut publicKey = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let publicKey = &mut publicKey[..privateKey.public_key_len()];
        // TODO: error handling
        privateKey.compute_public_key(publicKey);
        
        let derivedKey = agreement::agree_ephemeral(privateKey, &agreement::ECDH_P256, 
        untrustedForiegnKey, ring::error::Unspecified,
        |secret| {
            // TODO: error handling
            let saltedSecret = secret.to_vec();
            for salt in salts.iter() {
                let saltedSecret = salt.apply(&saltedSecret);
            }
            let derivedKey = digest::digest(&digest::SHA512, &saltedSecret[..]);
            Ok((*derivedKey.as_ref()).to_vec())
        }).unwrap();

        let mut aesKey = [0u8; 16];
        let mut ivKey = [0u8; 16];
        let mut hmacKey = [0u8; 32];
        &aesKey.clone_from_slice(&derivedKey[0..16]);
        &ivKey.clone_from_slice(&derivedKey[16..32]);
        &hmacKey.clone_from_slice(&derivedKey[32..64]);

        
        Crypto{salts, publicKey: publicKey.to_vec(), aesKey, ivKey, hmacKey}
    }

    /// Calculates the number of bytes needed to hold the input after padding is applied
    pub fn aligned_len(input: &[u8]) -> usize {
        return input.len() + (16 - input.len() % 16)
    }

    /// Encrypts a plaintext into a ciphertext
    ///
    /// # Arguments
    /// * iv - the IV for the encryption (must be exactly 16 bytes)
    /// * plaintext - the plaintext to be encrypted
    /// * ciphertext - the result of the encryption (use Crypto::aligned_len(plaintext) to determine the size this slice must be)
    pub fn encrypt(&self, iv: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) {
        let mut readBuf = RefReadBuffer::new(plaintext);
        let mut writeBuf = RefWriteBuffer::new(ciphertext);
        let mut encryptor = aes::cbc_encryptor(KeySize::KeySize128, &self.aesKey, iv, blockmodes::PkcsPadding);
        encryptor.encrypt(&mut readBuf, &mut writeBuf, true);
    }

    /// Decrypts a ciphertext into a plaintext
    ///
    /// # Arguments
    /// * iv - the IV used during encryption (must be exactly 16 bytes)
    /// * ciphertext - the ciphertext to be decrypted
    /// * plaintext - the result of the decryption (length is awkward here, will need to fix) 
    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) {
        let mut readBuf = RefReadBuffer::new(ciphertext);
        let mut writeBuf = RefWriteBuffer::new(plaintext);
        let mut decryptor = aes::cbc_decryptor(KeySize::KeySize128, &self.aesKey, iv, blockmodes::PkcsPadding);
        decryptor.decrypt(&mut readBuf, &mut writeBuf, true);
    }

    /// Creates a signature for a slice
    ///
    /// # Arguments
    /// * data - the data to be signed
    /// * signature - the rusult of the signature (must be exactly 32 bytes)
    pub fn sign(&self, data: &[u8], signature: &mut [u8]) {
        let key = hmac::SigningKey::new(&digest::SHA256, &self.hmacKey[..]);
        let hash = hmac::sign(&key, data);
        signature.clone_from_slice(hash.as_ref());
    }

    /// Verifies a signature was produced from the slice
    /// # Arguments
    /// * data - the data that was signed
    /// * signature - the signature of the data
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> bool {
        let key = hmac::VerificationKey::new(&digest::SHA256, &self.hmacKey[..]);
        let verification = hmac::verify(&key, data, signature);
        match verification {
            Ok(_) => true,
            Err(_) => false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn new_crypto() -> Crypto {
        let foreignPublicKey = "041db1e7943878b28c773228ebdcfb05b985be4a386a55f50066231360785f61b60038caf182d712d86c8a28a0e7e2733a0391b1169ef2905e4e21555b432b262d"
            .from_hex().unwrap();
        Crypto::new(&foreignPublicKey[..])
    }

    #[test]
    fn alignment_works() {
        let alignment = Crypto::aligned_len(&[0u8;4][..]);
        assert_eq!(alignment, 16);
        let alignment = Crypto::aligned_len(&[0u8;16][..]);
        assert_eq!(alignment, 32);
    }

    #[test]
    fn prepend_works() {
        let salt = Salt::Prepend(vec![1,2,3]);
        let result: Vec<u8> = salt.apply(&vec![4,5,6]);
        assert_eq!(result, [1,2,3,4,5,6]);
    }

    #[test]
    fn append_works() {
        let salt = Salt::Append(vec![4,5,6]);
        let result = salt.apply(&vec![1,2,3]);
        assert_eq!(result, [1,2,3,4,5,6]);
    }

    #[test]
    fn new_crypto_works() {
        let crypto = new_crypto();
    }

    #[test]
    fn encrypt_works() {
        let plaintext = String::from("Test").into_bytes();
        let mut ciphertext = vec![0xa0u8; Crypto::aligned_len(&plaintext[..])];
        let crypto = new_crypto();
        let iv = [0xb0u8; 16];
        crypto.encrypt(&iv[..], &plaintext[..], &mut ciphertext[..]);
        assert_eq!(ciphertext.len(), 16);
        assert_ne!(ciphertext, &[0xa0u8;16][..]);
    }

    #[test]
    fn decrypt_works() {
        let plaintext = String::from("Test").into_bytes();
        let mut ciphertext = vec![0xa0u8; Crypto::aligned_len(&plaintext[..])];
        let crypto = new_crypto();
        let iv = [0xb0u8; 16];
        crypto.encrypt(&iv[..], &plaintext[..], &mut ciphertext[..]);

        let mut newPlaintext = vec![0u8; plaintext.len()];
        crypto.decrypt(&iv[..], &ciphertext[..], &mut newPlaintext[..]);
        assert_eq!(plaintext, newPlaintext);
    }

    #[test]
    fn sign_works() {
        let plaintext = String::from("Test").into_bytes();
        let mut signature = [0xa0u8;32];
        let crypto = new_crypto();
        crypto.sign(&plaintext[..], &mut signature);
        assert_ne!(signature, &[0xa0u8;32][..]);
    }

    #[test]
    fn verify_works() {
        let plaintext = String::from("Test").into_bytes();
        let mut signature = [0xa0u8;32];
        let crypto = new_crypto();
        crypto.sign(&plaintext[..], &mut signature);
        assert!(crypto.verify(&plaintext[..], &signature[..]));
    }
}

