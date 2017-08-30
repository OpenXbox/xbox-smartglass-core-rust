extern crate nom;
extern crate protocol;

use std::io::{Read, Write};

use self::nom::*;
use self::protocol::{Parcel, DynArray, Error};
use ::serialize::*;

/// A representation of the weird serialization format of strings in SG packets
/// NOTE: this will not work with serde
#[derive(Debug,PartialEq,Eq,Clone)]
pub struct SGString {
    data: Vec<u8>, // make this a DynArray straight away?
    terminator: u8,
}

impl SGString {
    /// Creates an `SGString` from a rust `String`
    pub fn from_str(string: String) -> SGString {
        SGString {
            //len: string.len() as u16,
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
}

impl Parcel for SGString {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let data = DynArray::<i16, u8>::read(read)?;
        let term = u8::read(read)?;

        // Error here if the terminator isn't 0

        let sgstring = SGString::from_str(
            String::from_utf8(data.elements)?
        );

        Ok(sgstring)
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        let data = DynArray::<i16, u8>::new(self.data.clone());
        data.write(write);
        self.terminator.write(write);

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UUID {
    len: i16,
    value: String
}

impl UUID {
    pub fn from_string(string: String) -> UUID {
        UUID {
            len: string.len() as i16,
            value: string
        }
    }
}

impl Parcel for UUID {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let data = DynArray::<i16, u8>::read(read)?;
        Ok(UUID {
            len: data.elements.len() as i16,
            value: String::from_utf8(data.elements)?
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        let data = DynArray::<i16, u8>::new(self.value.clone().into_bytes());
        data.write(write);
        Ok(())
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
        let result = SGString::from_raw_bytes(b"\x00\x04test\x00");

        match result {
            Ok(parsed) => {
                assert_eq!(parsed, SGString::from_str(String::from("test")));
            },
            _ => assert!(false)
        }
    }

    #[test]
    fn serialize_works() {
        let serialized = b"\x00\x04test\x00";
        let sgstring = SGString::from_str(String::from("test"));

        assert_eq!(serialized, sgstring.raw_bytes().unwrap().as_slice());
    }
}
