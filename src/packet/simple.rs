extern crate protocol;

use std::io::{Read, Write};

use ::packet::{Type, Header};
use ::util::{SGString, UUID, PublicKey};
use self::protocol::{Parcel, DynArray};

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
    unk: u16,
    client_type: u32,  // todo: enumify
    flags: u32
});

define_packet!(DiscoveryResponseData {
    flags: u32,
    client_type: u16,  // todo: enumify
    name: SGString,
    uuid: UUID,
    padding: [u8; 5],
    certificate: DynArray<u16, u8> // todo: create a type for this
});

// We don't have test data for this
define_packet!(PowerOnRequestData {
    live_id: SGString
});

define_packet!(ConnectRequestUnprotectedData {
    sg_uuid: [u8; 16], // todo: allow UUID parsing to bytes rather than string
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

#[cfg(test)]
mod test {
    use super::*;
    use std::string;
    use ::packet;
    use ::state::*;
    use ::sgcrypto;

    fn new_connected_state() -> SGState {
        let crypto = ::sgcrypto::test::from_secret(include_bytes!("test/secret"));
        let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
        SGState::Connected(state)
    }

    #[test]
    fn parse_discovery_request_works() {
        let data = include_bytes!("test/discovery_request");
        let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

        match packet {
            packet::Packet::DiscoveryRequest(header, data) => {
                assert_eq!(header.pkt_type, packet::Type::DiscoveryRequest);
                assert_eq!(header.unprotected_payload_length, 10);
                assert_eq!(header.protected_payload_length, 0);
                assert_eq!(header.version, 0);

                assert_eq!(data.client_type, 8); // Android - todo: enumify
                assert_eq!(data.flags, 2);
            },
            _ => panic!("Wrong type")
        }
    }

    #[test]
    fn rebuild_discovery_request_works() {
        let data = include_bytes!("test/discovery_request");
        let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes(&SGState::Disconnected).unwrap());
    }

    #[test]
    fn parse_discovery_response_works() {
        let data = include_bytes!("test/discovery_response");
        let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

        match packet {
            packet::Packet::DiscoveryResponse(header, data) => {
                assert_eq!(header.pkt_type, packet::Type::DiscoveryResponse);
                assert_eq!(header.unprotected_payload_length, 648);
                assert_eq!(header.protected_payload_length, 0);
                assert_eq!(header.version, 2);;
                // Protocol crate also exports a String type, dunno how to properly handle this yet though, so this'll have to do for now
                assert_eq!(data.name, SGString::from_str(string::String::from("XboxOne")));
                assert_eq!(data.uuid, UUID::from_string(string::String::from("DE305D54-75B4-431B-ADB2-EB6B9E546014")));
                assert_eq!(data.certificate.elements.len(), 587); // todo: properly parse cert
            },
            _ => panic!("Wrong type")
        }
    }

    #[test]
    fn rebuild_discovery_response_works() {
        let data = include_bytes!("test/discovery_response");
        let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes(&SGState::Disconnected).unwrap());
    }

    // #[test]
    // fn parse_connect_request_unprotected_data_works() {
    //     let data = include_bytes!("test/connect_request");
    //     let crypto = ::sgcrypto::test::from_secret(include_bytes!("test/secret"));
    //     let packet = Packet::from_raw_bytes_protected(data, &crypto).unwrap();

    //     match packet {
    //         Packet::ConnectRequest(header, unprotected_data, protected_data) => {
    //             assert_eq!(header.pkt_type, packet::Type::ConnectRequest);
    //             assert_eq!(header.unprotected_payload_length, 98);
    //             assert_eq!(header.protected_payload_length, 47);
    //             assert_eq!(header.version, 2);

    //             assert_eq!(unprotected_data.sg_uuid, [222, 48, 93, 84, 117, 180, 67, 27, 173, 178, 235, 107, 158, 84, 96, 20]);
    //             assert_eq!(unprotected_data.public_key_type, 0);
    //             assert_eq!(unprotected_data.public_key_1, [255u8; 32]);
    //             assert_eq!(unprotected_data.public_key_2, [255u8; 32]);
    //             assert_eq!(unprotected_data.iv, [41, 121, 210, 94, 160, 61, 151, 245, 143, 70, 147, 10, 40, 139, 245, 210]);

    //             assert_eq!(protected_data.userhash, SGString::from_str(string::String::from("deadbeefdeadbeefde")));
    //             assert_eq!(protected_data.jwt, SGString::from_str(string::String::from("dummy_token")));
    //             assert_eq!(protected_data.connect_request_num, 0);
    //             assert_eq!(protected_data.connect_request_group_start, 0);
    //             assert_eq!(protected_data.connect_request_group_end, 2);
    //         },
    //         _ => panic!("Wrong type")
    //     }
    // }

    #[test]
    fn parse_connect_response_works() {
        let data = include_bytes!("test/connect_response");
        let sgstate = new_connected_state();
        let packet = packet::Packet::read(data, &sgstate).unwrap();

        match packet {
            packet::Packet::ConnectResponse(header, unprotected_data, protected_data) => {
                assert_eq!(header.pkt_type, packet::Type::ConnectResponse);
                assert_eq!(header.unprotected_payload_length, 16);
                assert_eq!(header.protected_payload_length, 8);
                assert_eq!(header.version, 2);
                assert_eq!(unprotected_data.iv, [198, 55, 50, 2, 189, 253, 17, 103, 207, 150,147, 73, 29, 34, 50, 42]);

                assert_eq!(protected_data.connect_request, 0);
                assert_eq!(protected_data.pairing_state, 0);
                assert_eq!(protected_data.participant_id, 31);
            },
            _ => panic!("Wrong type")
        }
    }

    #[test]
    fn repack_connect_response_works() {
        let data = include_bytes!("test/connect_response");
        let sgstate = new_connected_state();
        let packet = packet::Packet::read(data, &sgstate).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes(&sgstate).unwrap());
    }
}
