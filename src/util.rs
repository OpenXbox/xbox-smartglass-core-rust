/// A representation of the weird serialization format of strings in SG packets
/// NOTE: this will not work with serde
pub struct SGString {
    len: u16,
    data: Vec<u8>,
    terminator: u8,
}

impl SGString {
    /// Creates an `SGString` from a rust `String`
    pub fn from_str(string: String) -> SGString {
        SGString {
            len: string.len() as u16,
            data: string.into_bytes(),
            terminator: 0
        }
        
    }

    /// Creates a rust `String` from an `SGString`
    pub fn to_str(&self) -> String {
        // Safe to unwrap because the data came from a String
        let result = String::from_utf8(self.data.clone()).unwrap();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_works() {
        let string = String::from("Testing");
        let sgstring = SGString::from_str(string);
        assert_eq!(7, sgstring.len)
    }

    #[test]
    fn conversion_works() {
        let string = String::from("Testing");
        let sgstring = SGString::from_str(string.clone());
        assert_eq!(string, sgstring.to_str())
    }
}