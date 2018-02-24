use std::io::{Read, Write};

use ::packet::{Type, Header};
use ::util::{SGString, UUID, PublicKey, Certificate};

use protocol;
use protocol::Parcel;

#[derive(Debug, Clone)]
pub struct SimpleHeader {
    pub pkt_type: Type,
    pub unprotected_payload_length: u16,
    pub protected_payload_length: u16, // This is only sometimes here!
    pub version: u16
}

impl SimpleHeader {
    pub fn new(pkt_type: Type, version: u16) -> Self {
        SimpleHeader {
            pkt_type: pkt_type,
            unprotected_payload_length: 0,
            protected_payload_length: 0,
            version: version
        }
    }
}

impl Parcel for SimpleHeader {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        let pkt_type = Type::read(read)?;

        Ok(SimpleHeader {
            pkt_type: pkt_type,
            unprotected_payload_length: u16::read(read)?,
            protected_payload_length: if pkt_type.has_protected_data() { u16::read(read)? } else { 0 },
            version: u16::read(read)?
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
        self.pkt_type.write(write)?;
        self.unprotected_payload_length.write(write)?;
        if self.pkt_type.has_protected_data() {
            self.protected_payload_length.write(write)?;
        }
        self.version.write(write)?;

        Ok(())
    }
}

impl Header for SimpleHeader {
    fn set_protected_payload_length(&mut self, value: u16) {
        self.protected_payload_length = value;
    }

    fn set_unprotected_payload_length(&mut self, value: u16) {
        self.unprotected_payload_length = value;
    }
}

// Data definitions. The define_packet macro implements Parcel for us on structs.
#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct DiscoveryRequestData {
    pub flags: u32,
    pub client_type: u16,  // todo: enumify
    pub minimum_version: u16,
    pub maximum_version: u16
}

#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct DiscoveryResponseData {
    pub flags: u32,
    pub client_type: u16,  // todo: enumify
    pub name: SGString,
    pub uuid: UUID<String>,
    pub padding: [u8; 5],
    pub certificate: Certificate
}

// We don't have test data for this
#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct PowerOnRequestData {
    pub live_id: SGString
}

#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct ConnectRequestUnprotectedData {
    pub sg_uuid: UUID<u8>,
    pub public_key: PublicKey,
    pub iv: [u8;16]
}

#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct ConnectRequestProtectedData {
    pub userhash: SGString,
    pub jwt: SGString,
    pub request_num: u32,
    pub request_group_start: u32,
    pub request_group_end: u32
}

#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct ConnectResponseUnprotectedData {
    pub iv: [u8;16]
}

#[derive(Protocol, Clone, Debug, PartialEq)]
pub struct ConnectResponseProtectedData {
    pub connect_request: u16,
    pub pairing_state: u16,
    pub participant_id: u32
}
