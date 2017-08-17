extern crate nom;

use self::nom::*;

/// A representation of the weird serialization format of strings in SG packets
/// NOTE: this will not work with serde
#[derive(Debug,PartialEq,Eq,Clone)]
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
        result
    }

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
        assert_eq!(7, sgstring.len)
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
}
