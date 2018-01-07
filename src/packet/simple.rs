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
define_packet!(DiscoveryRequestData {
    flags: u32,
    client_type: u16,  // todo: enumify
    minimum_version: u16,
    maximum_version: u16
});

define_packet!(DiscoveryResponseData {
    flags: u32,
    client_type: u16,  // todo: enumify
    name: SGString,
    uuid: UUID<String>,
    padding: [u8; 5],
    certificate: Certificate
});

// We don't have test data for this
define_packet!(PowerOnRequestData {
    live_id: SGString
});

define_packet!(ConnectRequestUnprotectedData {
    sg_uuid: UUID<u8>,
    public_key: PublicKey,
    iv: [u8;16]
});

define_packet!(ConnectRequestProtectedData {
    userhash: SGString,
    jwt: SGString,
    request_num: u32,
    request_group_start: u32,
    request_group_end: u32
});

define_packet!(ConnectResponseUnprotectedData {
    iv: [u8;16]
});

define_packet!(ConnectResponseProtectedData {
    connect_request: u16,
    pairing_state: u16,
    participant_id: u32
});
