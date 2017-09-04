extern crate nom;
extern crate protocol;

use std::io::{Read, Write, Cursor};

use ::util::{SGString, UUID};
use ::packet;
use ::sgcrypto::Crypto;
use ::state::*;
use self::nom::*;
use self::protocol::*;

#[derive(Debug)]
enum Packet {
    PowerOnRequest(SimpleHeader, PowerOnRequestData),
    DiscoveryRequest(SimpleHeader, DiscoveryRequestData),
    DiscoveryResponse(SimpleHeader, DiscoveryResponseData),
    ConnectRequest(SimpleHeader, ConnectRequestUnprotectedData, ConnectRequestProtectedData),
    ConnectResponse(SimpleHeader, ConnectResponseUnprotectedData, ConnectResponseProtectedData),
    Message
}

impl Packet {
    fn read(input: &[u8], state: &SGState) -> Result<Self, Error> {
        let mut reader = Cursor::new(input);
        let pkt_type = packet::Type::read(&mut reader)?;
        reader.set_position(0);

        match pkt_type {
            packet::Type::PowerOnRequest |
            packet::Type::DiscoveryRequest |
            packet::Type::DiscoveryResponse |
            packet::Type::ConnectRequest => {
                if let SGState::Disconnected = *state {
                    return Packet::read_simple(&mut reader, &state)
                }
                Err("Invalid State".into())
            }
            packet::Type::ConnectResponse => {
                if let SGState::Connected(ref internal_state) = *state {
                    let data_len = input.len() - 32;
                    if internal_state.crypto.verify(&input[..data_len], &input[data_len..]).is_err() {
                        return Err("Invalid signature".into())
                    }
                    return Packet::read_simple(&mut reader, &state)
                }
                Err("Invalid State".into())
            }
            packet::Type::Message => Ok(Packet::Message)
        }
    }

    fn read_simple(reader: &mut Read, state: &SGState) -> Result<Self, Error> {
        let header = SimpleHeader::read(reader)?;
        match header.pkt_type {
            packet::Type::PowerOnRequest => {
                Ok(Packet::PowerOnRequest(
                    header,
                    PowerOnRequestData::read(reader)?
                ))
            },
            packet::Type::DiscoveryRequest => {
                Ok(Packet::DiscoveryRequest(
                    header,
                    DiscoveryRequestData::read(reader)?
                ))
            },
            packet::Type::DiscoveryResponse => {
                Ok(Packet::DiscoveryResponse(
                    header,
                    DiscoveryResponseData::read(reader)?
                ))
            },
            packet::Type::ConnectRequest => {
                Err("Cannot act as a server".into())
            },
            packet::Type::ConnectResponse => {
                // I wish we didn't have to recheck this. Maybe move it into a different method?
                if let SGState::Connected(ref state) = *state {
                    let unprotected = ConnectResponseUnprotectedData::read(reader)?;
                    let protected_len = header.protected_payload_length as usize;
                    let mut protected_buf = Vec::<u8>::new();
                    let mut decrypted_buf = vec![0u8; protected_len];
                    let buf_size = reader.read_to_end(&mut protected_buf)?;
                    &protected_buf.split_off(buf_size - 32);
                    state.crypto.decrypt(&unprotected.iv, &protected_buf, &mut decrypted_buf);
                    let protected = ConnectResponseProtectedData::from_raw_bytes(&decrypted_buf)?;

                    return Ok(Packet::ConnectResponse(
                        header,
                        unprotected,
                        protected
                    ));
                }
                Err("Invalid State".into())
            }
            _ => Err("Incorrect Type".into())
        }
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        match *self {
            Packet::PowerOnRequest(ref header, ref data) => {
                header.write(write);
                data.write(write);
            },
            Packet::DiscoveryRequest(ref header, ref data) => {
                header.write(write);
                data.write(write);
                // Something like this could be possible to get around the size thing.
                // let mut buffer = Cursor::new(Vec::new());
                // data.write(&mut buffer);

                // header.pkt_type.write(write);
                // println!("{:?}", buffer.position());
                // (buffer.position() as i16).write(write);
                // header.version.write(write);
                // write.write_all(buffer.into_inner().as_slice());
            },
            Packet::DiscoveryResponse(ref header, ref data) => {
                header.write(write);
                data.write(write);
            },
            Packet::ConnectRequest(ref header, ref unprotected_data, ref protected_data) => {
                header.write(write);
                unprotected_data.write(write);
            },
            Packet::ConnectResponse(ref header, ref unprotected_data, ref protected_data) => {
                header.write(write);
                unprotected_data.write(write);
            },
            _ => ()
        }

        Ok(())
    }

    fn raw_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Cursor::new(Vec::new());
        self.write(&mut buffer)?;

        Ok(buffer.into_inner())
    }
}

#[derive(Debug)]
pub struct SimpleHeader {
    pub pkt_type: packet::Type,
    pub unprotected_payload_length: u16,
    pub protected_payload_length: u16, // This is only sometimes here!
    pub version: u16
}

impl SimpleHeader {
    fn new(pkt_type: packet::Type, version: u16) -> Result<Self, Error> {
        Ok(SimpleHeader {
            pkt_type: pkt_type,
            unprotected_payload_length: 0,
            protected_payload_length: 0,
            version: version
        })
    }
}

impl Parcel for SimpleHeader {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let pkt_type = packet::Type::read(read)?;

        Ok(SimpleHeader {
            pkt_type: pkt_type,
            unprotected_payload_length: u16::read(read)?,
            protected_payload_length: if pkt_type.has_protected_data() { u16::read(read)? } else { 0 },
            version: u16::read(read)?
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        self.pkt_type.write(write);
        self.unprotected_payload_length.write(write);
        if self.pkt_type.has_protected_data() {
            self.protected_payload_length.write(write);
        }
        self.version.write(write);

        Ok(())
    }
}

// Placeholder
#[derive(Debug)]
pub struct MessageHeader {
    pkt_type: packet::Type
}

// discovery_request = 'discovery_request' / Struct(
//     'unk' / Int16ub,
//     'client_type' / Int32ub,
//     'flags' / Int32ub
// ) / StructObj

// Data definitions. The define_packet macro implements Parcel for us on structs.
define_packet!(DiscoveryRequestData {
    unk: u16,
    client_type: u32,
    flags: u32
});

// discover_response = 'discovery_response' / Struct(
//     'flags' / Int32ub,
//     'type' / Int16ub,
//     'name' / SGString('utf8'),
//     'uuid' / UUIDAdapter('utf8'),
//     Padding(5),
//     'cert' / CertificateAdapter()
// ) / StructObj

define_packet!(DiscoveryResponseData {
    flags: u32,
    client_type: u16,
    name: SGString,
    uuid: UUID,
    padding: [u8; 5],
    certificate: DynArray<u16, u8> // todo: create a type for this
});

// power_request = 'power_request' / Struct(
//     'liveid' / SGString('utf8')
// ) / StructObj

// We don't have test data for this
define_packet!(PowerOnRequestData {
    liveid: SGString
});

// connect_request_unprotected = 'connect_request_unprotected' / Struct(
//     'sg_uuid' / UUIDAdapter(),
//     'public_key_type' / Int16ub,
//     'public_key' / Bytes(0x40),
//     'iv' / Bytes(0x10)
// ) / StructObj

define_packet!(ConnectRequestUnprotectedData {
    sg_uuid: [u8; 16], // todo: allow UUID parsing to bytes rather than string
    public_key_type: u16,
    public_key_1: [u8; 32], // todo: fix this, it complains about Clone not being implemented if you go above 32
    public_key_2: [u8; 32],
    iv: [u8;16]
});

// connect_request_protected = 'connect_request_protected' / Struct(
//     'userhash' / SGString('utf8'),
//     'jwt' / SGString('utf8'),
//     'connect_request_num' / Int32ub,
//     'connect_request_group_start' / Int32ub,
//     'connect_request_group_end' / Int32ub
// ) / StructObj

define_packet!(ConnectRequestProtectedData {
    userhash: SGString,
    jwt: SGString,
    connect_request_num: u32,
    connect_request_group_start: u32,
    connect_request_group_end: u32
});

// connect_response_unprotected = 'connect_response_unprotected' / Struct(
//     'iv' / Bytes(0x10)
// ) / StructObj

define_packet!(ConnectResponseUnprotectedData {
    iv: [u8;16]
});

// connect_response_protected = 'connect_response_protected' / Struct(
//     'connect_result' / Int16ub,
//     'pairing_state' / Int16ub,
//     'participant_id' / Int32ub
// ) / StructObj

define_packet!(ConnectResponseProtectedData {
    connect_request: u16,
    pairing_state: u16,
    participant_id: u32
});

// struct = 'simple_message' / Struct(
//     'header' / header,
//     'unprotected_payload' / Switch(
//         this.header.pkt_type, {
//             PacketType.PowerOnRequest: power_request,
//             PacketType.DiscoveryRequest: discovery_request,
//             PacketType.DiscoveryResponse: discover_response,
//             PacketType.ConnectRequest: connect_request_unprotected,
//             PacketType.ConnectResponse: connect_response_unprotected
//         }
//     ),
//     'protected_payload' / CryptoTunnel(
//         Switch(
//             this.header.pkt_type, {
//                 PacketType.ConnectRequest: connect_request_protected,
//                 PacketType.ConnectResponse: connect_response_protected
//             },
//             Pass
//         )
//     )
// ) / StructObj

#[cfg(test)]
mod test {
    use super::*;
    use std::string;

    #[test]
    fn parse_discovery_request_works() {
        let data = include_bytes!("test/discovery_request");
        let packet = Packet::read(data, &SGState::Disconnected).unwrap();

        match packet {
            Packet::DiscoveryRequest(header, data) => {
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
        let packet = Packet::read(data, &SGState::Disconnected).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes().unwrap());
    }

    #[test]
    fn parse_discovery_response_works() {
        let data = include_bytes!("test/discovery_response");
        let packet = Packet::read(data, &SGState::Disconnected).unwrap();

        match packet {
            Packet::DiscoveryResponse(header, data) => {
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
        let packet = Packet::read(data, &SGState::Disconnected).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes().unwrap());
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
    fn parse_connect_response_unprotected_data_works() {
        let data = include_bytes!("test/connect_response");
        let crypto = ::sgcrypto::test::from_secret(include_bytes!("test/secret"));
        let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
        let packet = Packet::read(data, &SGState::Connected(state)).unwrap();

        match packet {
            Packet::ConnectResponse(header, unprotected_data, protected_data) => {
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
}
