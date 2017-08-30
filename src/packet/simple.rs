extern crate nom;
extern crate protocol;

use std::io::{Read, Write};

use ::util::{SGString, UUID};
use ::packet;
use self::nom::*;
use self::protocol::*;

#[derive(Debug)]
enum Packet {
    DiscoveryRequest(SimpleHeader, DiscoveryRequestData),
    DiscoveryResponse(SimpleHeader, DiscoveryResponseData),
    Message
}

impl Packet {
    fn new(data: DiscoveryRequestData) -> Result<Self, Error> {
        Ok(Packet::DiscoveryRequest(
            SimpleHeader::new(packet::Type::DiscoveryRequest, 0)?,
            data
        ))
    }
}

impl Parcel for Packet {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let header = Header::read(read)?;

        let packet = match header {
            Header::Simple(header) => match header.pkt_type {
                packet::Type::DiscoveryRequest => {
                    Packet::DiscoveryRequest(
                        header,
                        DiscoveryRequestData::read(read)?
                    )
                },
                packet::Type::DiscoveryResponse => {
                    Packet::DiscoveryResponse(
                        header,
                        DiscoveryResponseData::read(read)?
                    )
                }
                _ => Packet::Message // placeholder
            },
            Header::Message(header) => Packet::Message
        };

        Ok(packet)
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        match *self {
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
            _ => ()
        }

        Ok(())
    }
}

// Header enum so we have a single place to read/"write" headers. In reality we unpack the parsed header and insert that in the Packet enum.
#[derive(Debug)]
enum Header {
    Simple(SimpleHeader),
    Message(MessageHeader)
}

impl Parcel for Header {
    fn read(read: &mut Read) -> Result<Self, Error> {
        let pkt_type = packet::Type::read(read).unwrap();

        let header = match pkt_type {
            packet::Type::ConnectRequest |
            packet::Type::ConnectResponse |
            packet::Type::DiscoveryRequest |
            packet::Type::DiscoveryResponse |
            packet::Type::PowerOnRequest => Header::Simple(SimpleHeader {
                pkt_type: pkt_type,
                unprotected_payload_length: i16::read(read)?,
                protected_payload_length: if pkt_type.has_protected_data() { i16::read(read)? } else { 0 },
                version: i16::read(read)?
            }),
            packet::Type::Message => Header::Message(MessageHeader {
                pkt_type
            })
        };

        Ok(header)
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        match *self {
            Header::Simple(ref header) => {
                header.pkt_type.write(write);
                header.unprotected_payload_length.write(write);
                if header.pkt_type.has_protected_data() {
                    header.protected_payload_length.write(write);
                }
                header.version.write(write);
            },
            Header::Message(ref header) => {
                header.pkt_type.write(write);
            }
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct SimpleHeader {
    pub pkt_type: packet::Type,
    pub unprotected_payload_length: i16,
    pub protected_payload_length: i16, // This is only sometimes here!
    pub version: i16
}

impl SimpleHeader {
    fn new(pkt_type: packet::Type, version: i16) -> Result<Self, Error> {
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
            unprotected_payload_length: i16::read(read)?,
            protected_payload_length: if pkt_type.has_protected_data() { i16::read(read)? } else { 0 },
            version: i16::read(read)?
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

// Data definitions. The define_packet macro implements Parcel for us on structs.
define_packet!(DiscoveryRequestData {
    unk: i16,
    client_type: i32,
    flags: i32
});

define_packet!(DiscoveryResponseData {
    flags: u32,
    client_type: u16,
    name: SGString,
    uuid: UUID
});


// power_request = 'power_request' / Struct(
//     'liveid' / SGString('utf8')
// ) / StructObj


// discovery_request = 'discovery_request' / Struct(
//     'unk' / Int16ub,
//     'client_type' / Int32ub,
//     'flags' / Int32ub
// ) / StructObj


// discover_response = 'discovery_response' / Struct(
//     'flags' / Int32ub,
//     'type' / Int16ub,
//     'name' / SGString('utf8'),
//     'uuid' / UUIDAdapter('utf8'),
//     Padding(5),
//     'cert' / CertificateAdapter()
// ) / StructObj


// connect_request_unprotected = 'connect_request_unprotected' / Struct(
//     'sg_uuid' / UUIDAdapter(),
//     'public_key_type' / Int16ub,
//     'public_key' / Bytes(0x40),
//     'iv' / Bytes(0x10)
// ) / StructObj


// connect_request_protected = 'connect_request_protected' / Struct(
//     'userhash' / SGString('utf8'),
//     'jwt' / SGString('utf8'),
//     'connect_request_num' / Int32ub,
//     'connect_request_group_start' / Int32ub,
//     'connect_request_group_end' / Int32ub
// ) / StructObj


// connect_response_unprotected = 'connect_response_unprotected' / Struct(
//     'iv' / Bytes(0x10)
// ) / StructObj


// connect_response_protected = 'connect_response_protected' / Struct(
//     'connect_result' / Int16ub,
//     'pairing_state' / Int16ub,
//     'participant_id' / Int32ub
// ) / StructObj


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
        let packet = Packet::from_raw_bytes(data).unwrap();

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
    fn parse_discovery_response_works() {
        let data = include_bytes!("test/discovery_response");
        let packet = Packet::from_raw_bytes(data).unwrap();

        match packet {
            Packet::DiscoveryResponse(header, data) => {
                assert_eq!(header.pkt_type, packet::Type::DiscoveryResponse);
                assert_eq!(header.unprotected_payload_length, 648);
                assert_eq!(header.protected_payload_length, 0);
                assert_eq!(header.version, 2);;
                // Protocol crate also exports a String type, dunno how to properly handle this yet though, so this'll have to do for now
                assert_eq!(data.name, SGString::from_str(string::String::from("XboxOne")));
                assert_eq!(data.uuid, UUID::from_string(string::String::from("DE305D54-75B4-431B-ADB2-EB6B9E546014")));

                // I didn't even attempt to handle the certificate
            }
            _ => panic!("Wrong type")
        }
    }
}
