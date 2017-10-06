extern crate openssl;

use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;

use uuid::Uuid;
use protocol::{Parcel, DynArray, Error};
use protocol::String as PrefixedString;

/// A representation of the weird serialization format of strings in SG packets
/// NOTE: this will not work with serde
#[derive(Debug,PartialEq,Clone)]
pub struct SGString {
    value: PrefixedString<u16>,
    terminator: u8
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
            value: PrefixedString::<u16>::new(string),
            terminator: 0
        }
    }

    /// Creates a rust `String` from an `SGString`
    pub fn to_str(&self) -> String {
        // Safe to unwrap because the data came from a String
        self.value.value.clone()
    }

    pub fn value(&self) -> &String {
        &self.value.value
    }
}

impl Parcel for SGString {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let value = PrefixedString::<u16>::read(read)?;
        let terminator = u8::read(read)?;

        // Error here if the terminator isn't 0

        Ok(SGString {
            value, terminator
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        self.value.write(write)?;
        self.terminator.write(write)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct UUID<T: Parcel> {
    uuid: Uuid,
    _a: PhantomData<T>,
}

impl<T: Parcel> UUID<T> {
    pub fn new(uuid: Uuid) -> Self {
        UUID {
            uuid,
            _a: PhantomData
        }
    }

    pub fn into_format<U: Parcel>(self) -> UUID<U> {
        UUID {
            uuid: self.uuid,
            _a: PhantomData
        }
    }
}

impl Parcel for UUID<String> {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let data = DynArray::<u16, u8>::read(read)?;
        let uuid = Uuid::parse_str(&String::from_utf8(data.elements)?)?;
        Ok(Self::new(uuid))
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        let data = DynArray::<u16, u8>::new(self.uuid.hyphenated().to_string().to_uppercase().into_bytes());
        data.write(write)?;
        Ok(())
    }
}

impl Parcel for UUID<u8> {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let data: [u8; 16] = Parcel::read(read)?;
        let uuid = Uuid::from_bytes(&data)?;
        Ok(Self::new(uuid))
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        self.uuid.as_bytes().write(write)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct PublicKey {
    key_type: u16,
    key: [u8; 64]
}

impl PublicKey {
    pub fn new(key_type: u16, key: [u8; 64]) -> Self {
        PublicKey {
            key_type,
            key
        }
    }
}

implement_composite_type!(PublicKey { key_type, key });

impl fmt::Debug for PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "PublicKey {{ key_type: {}", self.key_type);
        self.key[..].fmt(formatter);
        write!(formatter, "}}")
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.key_type == other.key_type && self.key[..] == other.key[..]
    }
}

#[derive(Clone)]
pub struct Certificate {
    subject: String,
    public_key_type: u8,
    public_key: [u8; 64],
    data: DynArray<u16, u8>
}

impl Certificate {
    pub fn subject(&self) -> &String {
        &self.subject
    }

    pub fn public_key_type(&self) -> u8 {
        self.public_key_type
    }

    pub fn public_key(&self) -> &[u8; 64] {
        &self.public_key
    }
}

impl Parcel for Certificate {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let data = DynArray::<u16, u8>::read(read)?;

        let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::X9_62_PRIME256V1).unwrap();
        let form = openssl::ec::POINT_CONVERSION_UNCOMPRESSED;
        let mut ctx = openssl::bn::BigNumContext::new().unwrap();

        let cert = openssl::x509::X509::from_der(data.elements.as_slice()).unwrap();
        let subject = String::from_utf8(cert.subject_name().entries_by_nid(openssl::nid::COMMONNAME).next().unwrap().data().as_slice().to_vec()).unwrap();
        let key = cert.public_key().unwrap().ec_key().unwrap().public_key().unwrap().to_bytes(&group, form, &mut ctx).unwrap().to_vec();

        let public_key_type = key[0];
        let mut public_key = [0u8; 64];

        for (i, e) in key[1..].iter().enumerate() {
            public_key[i] = *e;
        }

        Ok(Certificate {
            subject,
            public_key_type,
            public_key,
            data
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        self.data.write(write)?;
        Ok(())
    }
}

impl fmt::Debug for Certificate {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "Certificate {{ subject: {} public_key_type: {} public_key: ", self.subject, self.public_key_type);
        self.public_key[..].fmt(formatter);
        write!(formatter, "}}")
    }
}

impl PartialEq for Certificate {
    fn eq(&self, other: &Certificate) -> bool {
        self.subject == other.subject &&
        self.public_key_type == other.public_key_type &&
        self.public_key[..] == other.public_key[..] &&
        self.data == other.data
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn encode_works() {
        let string = String::from("Testing");
        let sgstring = SGString::from_str(string);
        assert_eq!(7, sgstring.value().len())
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

    #[test]
    fn uuid_works() {
        let data = Uuid::parse_str("DE305D54-75B4-431B-ADB2-EB6B9E546014").unwrap();
        // let data = Uuid::new_v4();  // this doesn't work for whatever reason?
        let sg_uuid = UUID::<u8>::new(data);

        assert_eq!(sg_uuid.uuid, data);
    }
}
