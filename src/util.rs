extern crate nom;

use self::nom::*;
use ::serialize::*;

/// A representation of the weird serialization format of strings in SG packets
/// NOTE: this will not work with serde
#[derive(Debug,PartialEq,Eq,Clone)]
pub struct SGString {
    data: Vec<u8>,
    terminator: u8,
}

/// Represents an smartglass string
///
/// A smartglass string is a null-terminated pascal string.
/// That is, it's serialized form has a 16-bit size,
/// followed `size` UTF-8 bytes,
/// followed by a null byte
impl SGString {
    /// Creates an `SGString` from a rust `String`
    pub fn from_str(string: String) -> SGString {
        SGString {
            data: string.into_bytes(),
            terminator: 0
        }
        
    }

    /// Creates a rust `String` from an `SGString`
    pub fn to_str(&self) -> String {
        // Safe to unwrap because the data came from a String
        let result = String::from_utf8(self.data.clone()).unwrap();
        result
    }

    /// Parses a serialized form of an `SGString`
    pub fn parse(input: &[u8]) -> IResult<&[u8], SGString> {
        do_parse!(input,
            len: be_u16 >>
            val: map_res!(take!(len), |data: &[u8]| String::from_utf8(data.to_vec())) >>
            tag!(&[0][..]) >>
            (
                SGString::from_str(val)
            )
        )
    }
}

/// Serializes an SGString
impl Serialize for SGString {
    impl_serialize!(
        data,
        terminator
    );
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UUID {
    len: u16,
    value: String
}

impl UUID {
    pub fn from_string(string: String) -> UUID {
        UUID {
            len: string.len() as u16,
            value: string
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], UUID> {
        do_parse!(input,
            len: be_u16 >>
            value: map_res!(take!(len), |data: &[u8]| String::from_utf8(data.to_vec())) >>
            (
                UUID { len, value }
            )
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_works() {
        let string = String::from("Testing");
        let sgstring = SGString::from_str(string);
        assert_eq!(7, sgstring.data.len())
    }

    #[test]
    fn conversion_works() {
        let string = String::from("Testing");
        let sgstring = SGString::from_str(string.clone());
        assert_eq!(string, sgstring.to_str())
    }

    #[test]
    fn parse_works() {
        let parsed = SGString::parse(b"\x00\x04test\x00");
        match parsed {
            IResult::Done(remaining, sgstring) => {
                assert_eq!(sgstring, SGString::from_str(String::from("test")));
                assert_eq!(remaining.len(), 0);
            }
            _ => assert!(false)
        }
    }

    #[test]
    fn serialize_works() {
        let serialized = b"\x00\x04test\x00";
        let sgstring = SGString::from_str(String::from("test"));
        let size = sgstring.size();
        let mut vec = vec![0; size];
        sgstring.serialize(&mut vec[..]);
        assert_eq!(serialized, &vec[..])
    }
}
