extern crate rustc_serialize;
extern crate ring;
extern crate untrusted;
extern crate crypto;

use self::rustc_serialize::hex::FromHex;
use self::ring::{agreement, hmac, rand, digest};
use self::ring::error::Unspecified;
use self::untrusted::Input;
use self::crypto::aes;
use self::crypto::aes::KeySize;
use self::crypto::blockmodes;
use self::crypto::symmetriccipher::SymmetricCipherError;
use self::crypto::buffer::{RefReadBuffer, RefWriteBuffer, BufferResult};

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        // Todo: Add more errors here?
        Unspecified {
            from(SymmetricCipherError)
            from(Unspecified)
         }
         BufferOverflow { }
    }
}

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
    pub fn apply(&self, data: &Vec<u8>) -> Vec<u8> {
        match *self {
            Salt::Prepend(ref salt) => [&salt[..], &data[..]].concat(),
            Salt::Append(ref salt) => [&data[..], &salt[..]].concat()
        }
    }
}

/// The particular crypto ipmlementation used by SmartGlass
#[allow(dead_code)]
pub struct Crypto {
    pub_key: [u8; 40],
    aes_key: [u8;16],
    iv_key: [u8;16],
    hmac_key: [u8;32]
}

impl Crypto {
    /// Creates a new Crypto
    ///
    /// # Arguments
    /// * foreignPublicKey - The public key of the xbox one associated with the SG Session
    pub fn new(foreign_public_key: &[u8]) -> Crypto {
        let rng = rand::SystemRandom::new();
        // TODO: error handling
        Crypto::from_rand(foreign_public_key, rng)
    }

    fn from_rand<T>(foreign_public_key: &[u8], rng: T) -> Crypto
        where T: rand::SecureRandom {
         // Safe to unwrap here because the string is static and known to be valid
        //  text. We should never recieve anthing but Ok(val)
        let prepend_salt = Salt::Prepend("D637F1AAE2F0418C".from_hex().unwrap());
        let append_salt = Salt::Append("A8F81A574E228AB7".from_hex().unwrap());
        let salts = [prepend_salt, append_salt];

        let untrusted_foreign_key = Input::from(foreign_public_key);
        let private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng).unwrap();
        let mut public_key = [0u8; agreement::PUBLIC_KEY_MAX_LEN];
        let public_key = &mut public_key[..private_key.public_key_len()];
        // TODO: error handling
        private_key.compute_public_key(public_key).unwrap();

        let kdf =  |secret: &[u8]| {
            // TODO: error handling
            let mut salted_secret = secret.to_vec();
            for salt in salts.iter() {
                salted_secret = salt.apply(&salted_secret);
            }
            let derived_key = digest::digest(&digest::SHA512, &salted_secret[..]);
            Ok((*derived_key.as_ref()).to_vec())
        };

        let derived_key = agreement::agree_ephemeral(private_key, &agreement::ECDH_P256,
            untrusted_foreign_key, ring::error::Unspecified, kdf).unwrap();

        let mut pub_key = [0u8; 40];
        let mut aes_key = [0u8; 16];
        let mut iv_key = [0u8; 16];
        let mut hmac_key = [0u8; 32];
        &pub_key.clone_from_slice(&public_key[0..40]);
        &aes_key.clone_from_slice(&derived_key[0..16]);
        &iv_key.clone_from_slice(&derived_key[16..32]);
        &hmac_key.clone_from_slice(&derived_key[32..64]);

        Crypto{pub_key, aes_key, iv_key, hmac_key}
    }

    /// Calculates the number of bytes needed to hold the input after padding is applied
    pub fn aligned_len(len: usize) -> usize {
        if len % 16 == 0 {
           len
        } else {
            len + (16 - len % 16)
        }
    }

    /// Encrypts a plaintext into a ciphertext
    ///
    /// # Arguments
    /// * iv - the IV for the encryption (must be exactly 16 bytes)
    /// * plaintext - the plaintext to be encrypted
    /// * ciphertext - the result of the encryption (use Crypto::aligned_len(plaintext) to determine the size this slice must be)
    pub fn encrypt(&self, iv: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        let mut read_buf = RefReadBuffer::new(plaintext);
        let mut write_buf = RefWriteBuffer::new(ciphertext);
        let mut encryptor = 
        match plaintext.len() % 16 {
            0 => aes::cbc_encryptor(KeySize::KeySize128, &self.aes_key, iv, blockmodes::NoPadding),
            _ => aes::cbc_encryptor(KeySize::KeySize128, &self.aes_key, iv, blockmodes::PkcsPadding)
        };
        let res = encryptor.encrypt(&mut read_buf, &mut write_buf, true)?;
        match res {
            BufferResult::BufferOverflow => Err(Error::BufferOverflow),
            _ => Ok(())
        }
    }

    /// Decrypts a ciphertext into a plaintext
    ///
    /// # Arguments
    /// * iv - the IV used during encryption (must be exactly 16 bytes)
    /// * ciphertext - the ciphertext to be decrypted
    /// * plaintext - the result of the decryption (length is awkward here, will need to fix)
    pub fn decrypt(&self, iv: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) -> Result<(), Error> {
        let mut read_buf = RefReadBuffer::new(ciphertext);
        let mut write_buf = RefWriteBuffer::new(plaintext);
        let mut decryptor = aes::cbc_decryptor(KeySize::KeySize128, &self.aes_key, iv, blockmodes::PkcsPadding);
        let res = decryptor.decrypt(&mut read_buf, &mut write_buf, true)?;
        match res {
            BufferResult::BufferOverflow => Err(Error::BufferOverflow),
            _ => Ok(())
        }
    }

    /// Encryptes the plaintext using the IV key
    ///
    /// # Arguments
    /// * plaintext - the plaintext to be encrypted
    /// * ciphertext - the result of the encryption
    pub fn generate_iv(&self, plaintext: &[u8], ciphertext: &mut [u8]) -> Result<(), Error> {
        let mut read_buf = RefReadBuffer::new(plaintext);
        let mut write_buf = RefWriteBuffer::new(ciphertext);
        let mut encryptor = aes::cbc_encryptor(KeySize::KeySize128, &self.iv_key, &[0u8;16], blockmodes::NoPadding);
        let res = encryptor.encrypt(&mut read_buf, &mut write_buf, true)?;
        match res {
            BufferResult::BufferOverflow => Err(Error::BufferOverflow),
            _ => Ok(())
        }
    }

    /// Creates a signature for a slice
    ///
    /// # Arguments
    /// * data - the data to be signed
    /// * signature - the rusult of the signature (must be exactly 32 bytes)
    pub fn sign(&self, data: &[u8], signature: &mut [u8]) {
        let key = hmac::SigningKey::new(&digest::SHA256, &self.hmac_key[..]);
        let hash = hmac::sign(&key, data);
        signature.clone_from_slice(hash.as_ref());
    }

    /// Verifies a signature was produced from the slice
    /// # Arguments
    /// * data - the data that was signed
    /// * signature - the signature of the data
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), Error> {
        let key = hmac::VerificationKey::new(&digest::SHA256, &self.hmac_key[..]);
        hmac::verify(&key, data, signature)?;
        Ok(())
    }
}

pub mod tests {
    use super::*;

    pub fn from_secret(secret: &[u8]) -> Crypto {
        if secret.len() != 64 {
            panic!("Secret length should be exactly 64-bytes")
        }

        let mut aes_key = [0u8; 16];
        let mut iv_key = [0u8; 16];
        let mut hmac_key = [0u8; 32];
        &aes_key.clone_from_slice(&secret[0..16]);
        &iv_key.clone_from_slice(&secret[16..32]);
        &hmac_key.clone_from_slice(&secret[32..64]);

        Crypto{pub_key: [0u8; 40], aes_key, iv_key, hmac_key}
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn new_crypto() -> Crypto {
        let foreign_public_key = "041db1e7943878b28c773228ebdcfb05b985be4a386a55f50066231360785f61b60038caf182d712d86c8a28a0e7e2733a0391b1169ef2905e4e21555b432b262d"
            .from_hex().unwrap();
        Crypto::new(&foreign_public_key[..])
    }

    pub fn from_secret(secret: &[u8]) -> Crypto {
        if (secret.len() != 64) {
            panic!("Secret length should be exactly 64-bytes")
        }

        let mut aes_key = [0u8; 16];
        let mut iv_key = [0u8; 16];
        let mut hmac_key = [0u8; 32];
        &aes_key.clone_from_slice(&secret[0..16]);
        &iv_key.clone_from_slice(&secret[16..32]);
        &hmac_key.clone_from_slice(&secret[32..64]);

        Crypto{pub_key: [0u8; 40], aes_key, iv_key, hmac_key}
    }

    #[test]
    fn alignment_works() {
        let alignment = Crypto::aligned_len(4);
        assert_eq!(alignment, 16);
        let alignment = Crypto::aligned_len(16);
        assert_eq!(alignment, 16);
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
        let mut ciphertext = vec![0xa0u8; Crypto::aligned_len(plaintext.len())];
        let crypto = new_crypto();
        let iv = [0xb0u8; 16];
        let result = crypto.encrypt(&iv[..], &plaintext[..], &mut ciphertext[..]);
        assert!(!result.is_err());
        assert_eq!(ciphertext.len(), 16);
        assert_ne!(ciphertext, &[0xa0u8;16][..]);
    }

    fn encrypt_matches_python() {
        // encrypt 0xDEADBEEF using a known secret and iv

        // IV = generated via python (arbitrary)
        let iv = [0x51, 0x4a, 0xbc, 0x92, 0xea, 0x2a, 0x6e, 0xf7, 0x8e, 0x63, 0x80, 0x83, 0xb8, 0x58, 0x4b, 0x20];
        // Plaintext = 0xDEADBEEF + pkcs padding
        let plaintext = [0xde, 0xad, 0xbe, 0xef, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c];
        // Secret = from python project
        let crypto = from_secret(include_bytes!("test/secret"));
        let mut ciphertext = vec![0u8, 16];
        let result = crypto.decrypt(&iv[..], &plaintext[..], &mut ciphertext[..]);
        assert!(!result.is_err());
        // Expected Ciphertext = result of encrypt in python project
        assert_eq!(ciphertext, [0x64, 0x97, 0x23, 0x2a, 0x0e, 0x4e, 0x74, 0x34, 0x3c, 0x3a, 0x08, 0xb3, 0x68, 0x4b, 0x45, 0xf7])
    }

    #[test]
    fn decrypt_works() {
        let plaintext = String::from("Test").into_bytes();
        let mut ciphertext = vec![0xa0u8; Crypto::aligned_len(plaintext.len())];
        let crypto = new_crypto();
        let iv = [0xb0u8; 16];
        let enc_result = crypto.encrypt(&iv[..], &plaintext[..], &mut ciphertext[..]);
        assert!(!enc_result.is_err());

        let mut new_plaintext = vec![0u8; plaintext.len()];
        let dec_result = crypto.decrypt(&iv[..], &ciphertext[..], &mut new_plaintext[..]);
        assert!(!dec_result.is_err());
        assert_eq!(plaintext, new_plaintext);
    }

    #[test]
    fn generate_iv_works() {
        let crypto = from_secret(include_bytes!("test/secret"));
        let plaintext = include_bytes!("test/acknowledge");
        let mut iv = [0u8;16];

        let enc_result = crypto.generate_iv(&plaintext[..16], &mut iv);
        assert!(!enc_result.is_err());
        assert_eq!(iv, [42, 217, 39, 130, 232, 107, 46, 94, 109, 204, 111, 28, 45, 171, 13, 77]);
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
        assert!(!crypto.verify(&plaintext[..], &signature[..]).is_err());
    }
}

