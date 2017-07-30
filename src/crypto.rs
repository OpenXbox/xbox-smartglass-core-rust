extern crate rustc_serialize;

use self::rustc_serialize::hex::FromHex;

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
    salts: [Salt; 2]
}

impl Crypto {
    /// Creates a new Crypto
    ///
    /// # Arguments
    /// * foreignPublicKey - The public key of the xbox one associated with the SG Session
    pub fn new(foreignPublicKey: Vec<u8>) -> Crypto {
        // Safe to unwrap here because the string is static and known to be valid
        //  text. We should never recieve anthing but Ok(val)
        let prependSalt = Salt::Prepend("D637F1AAE2F0418C".from_hex().unwrap());
        let appendSalt = Salt::Append("A8F81A574E228AB7".from_hex().unwrap());
        Crypto{salts: [prependSalt, appendSalt]}
    }
}


#[cfg(test)]
mod test {
    use super::*;

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
}

