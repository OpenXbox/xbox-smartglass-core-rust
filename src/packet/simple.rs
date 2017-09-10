extern crate protocol;

use std::io;
use std::io::{Read, Write, Cursor, Seek};

use ::util::{SGString, UUID};
use ::packet;
use ::sgcrypto;
use ::sgcrypto::Crypto;
use ::state::*;
use self::protocol::{DynArray, Parcel};

#[derive(Debug)]
enum Packet {
    PowerOnRequest(SimpleHeader, PowerOnRequestData),
    DiscoveryRequest(SimpleHeader, DiscoveryRequestData),
    DiscoveryResponse(SimpleHeader, DiscoveryResponseData),
    ConnectRequest(SimpleHeader, ConnectRequestUnprotectedData, ConnectRequestProtectedData),
    ConnectResponse(SimpleHeader, ConnectResponseUnprotectedData, ConnectResponseProtectedData),
    Message
}

quick_error! {
    #[derive(Debug)]
    pub enum ReadError {
        Decrypt(err: sgcrypto::Error) { }
        IO(err: io::Error) { from() }
        Message(err: String) { from() }
        NotImplimented { }
        Read(err: protocol::Error) { from() }
        Signature(err: sgcrypto::Error) { }
        State(err: InvalidState) { from() }
        Type(pkt_type: packet::Type) { }

    }
}

quick_error! {
    #[derive(Debug)]
    pub enum WriteError {
        Encrypt(err: sgcrypto::Error) { }
        IO(err: io::Error) { from() }
        Message(err: String) { from() }
        NotImplimented { }
        Signature(err: sgcrypto::Error) { }
        State(err: InvalidState) { from() }
        Type(pkt_type: packet::Type) { }
        Write(err: protocol::Error) { from() }
    }
}

trait Header {
    fn set_protected_payload_length(&mut self, value: u16);
    fn set_unprotected_payload_length(&mut self, value: u16);
}

impl Packet {
    fn read(input: &[u8], state: &SGState) -> Result<Self, ReadError> {
        let mut reader = Cursor::new(input);
        let pkt_type = packet::Type::read(&mut reader)?;
        reader.set_position(0);

        match pkt_type {
            packet::Type::PowerOnRequest |
            packet::Type::DiscoveryRequest |
            packet::Type::DiscoveryResponse |
            packet::Type::ConnectRequest => {
                state.ensure_disconnected()?;
                Packet::read_simple(&mut reader, &state)
            }
            packet::Type::ConnectResponse => {
                let internal_state = state.ensure_connected()?;
                let data_len = input.len() - 32;
                internal_state.crypto.verify(&input[..data_len], &input[data_len..]).map_err(ReadError::Signature)?;
                Packet::read_simple(&mut reader, &state)
            }
            packet::Type::Message => Ok(Packet::Message)
        }
    }

    fn read_simple(reader: &mut Read, state: &SGState) -> Result<Self, ReadError> {
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
                Err(ReadError::NotImplimented)
            },
            packet::Type::ConnectResponse => {
                let internal_state = state.ensure_connected()?;
                let unprotected = ConnectResponseUnprotectedData::read(reader)?;
                let protected_len = header.protected_payload_length as usize;
                let decrypted_buf = Packet::decrypt(reader, &internal_state.crypto, protected_len, &unprotected.iv)?;
                let protected = ConnectResponseProtectedData::from_raw_bytes(&decrypted_buf)?;

                return Ok(Packet::ConnectResponse(
                    header,
                    unprotected,
                    protected
                ));
            }
            _ => Err(ReadError::Type(header.pkt_type))
        }
    }

    fn write(&self, write: &mut Cursor<Vec<u8>>, state: &SGState) -> Result<(), WriteError> {
        match *self {
            Packet::PowerOnRequest(ref header, ref data) => {
                Packet::write_unprotected(write, header, data)?;
            },
            Packet::DiscoveryRequest(ref header, ref data) => {
                Packet::write_unprotected(write, header, data)?;
            },
            Packet::DiscoveryResponse(ref header, ref data) => {
                Packet::write_unprotected(write, header, data)?;
            },
            Packet::ConnectRequest(ref header, ref unprotected_data, ref protected_data) => {
                header.write(write)?;
                unprotected_data.write(write)?;
            },
            Packet::ConnectResponse(ref header, ref unprotected_data, ref protected_data) => {
                let internal_state = state.ensure_connected()?;
                Packet::write_protected(write, &internal_state.crypto, &unprotected_data.iv, header, unprotected_data, protected_data)?;
            },
            _ => ()
        }

        Ok(())
    }

    fn write_unprotected<THead, TUnprotected>(write: &mut Cursor<Vec<u8>>, header: &THead, unprotected: &TUnprotected) -> Result<(), WriteError>
        where THead: Header + Clone + Parcel, TUnprotected: Parcel {
        let mut header_clone = header.clone();
        header.write(write)?;
        let header_len = write.position();
        unprotected.write(write)?;
        let unprotected_len = write.position() - header_len;
        header_clone.set_unprotected_payload_length(unprotected_len as u16);
        write.set_position(0);
        header.write(write)?;
        // TODO: Should this be safe and move the cursor to the end?q
        Ok(())
    }

    fn write_protected<THead, TUnprotected, TProtected>(write: &mut Cursor<Vec<u8>>, crypto: &Crypto, iv: &[u8], header: &THead, unprotected: &TUnprotected, protected: &TProtected) -> Result<(), WriteError>
        where THead: Header + Clone + Parcel, TUnprotected: Parcel, TProtected: Parcel  {
            let mut header_clone = header.clone();
            header.write(write)?;
            let header_len = write.position();
            unprotected.write(write)?;
            let unprotected_len = write.position() - header_len;
            let protected_len = Packet::encrypt(write, protected, crypto, iv)?;

            header_clone.set_unprotected_payload_length(unprotected_len as u16);
            header_clone.set_protected_payload_length(protected_len as u16);
            write.set_position(0);
            header_clone.write(write)?;
            write.set_position(header_len + unprotected_len + Crypto::aligned_len(protected_len as usize) as u64);
            Packet::sign(write, crypto)?;
            Ok(())
        }

    fn raw_bytes(&self, state: &SGState) -> Result<Vec<u8>, WriteError> {
        let mut buffer = Cursor::new(Vec::new());
        self.write(&mut buffer, state)?;

        Ok(buffer.into_inner())
    }

    fn decrypt(reader: &mut Read, crypto: &Crypto, protected_payload_length: usize, iv: &[u8]) -> Result<Vec<u8>, ReadError> {
        let mut protected_buf = Vec::<u8>::new();
        let mut decrypted_buf = vec![0u8; protected_payload_length];
        let buf_size = reader.read_to_end(&mut protected_buf)?;
        &protected_buf.split_off(buf_size - 32);
        crypto.decrypt(iv, &protected_buf, &mut decrypted_buf).map_err(ReadError::Decrypt)?;
        Ok(decrypted_buf)
    }

    // TODO: Find a way to make this less restrictive than Cursor
    fn encrypt<T>(writer: &mut Cursor<Vec<u8>>, data: &T, crypto: &Crypto, iv: &[u8]) -> Result<u64, WriteError> where T: Parcel {
        let mut buf = Cursor::new(Vec::<u8>::new());
        data.write(&mut buf)?;
        let protected_data_len = buf.position() as usize;
        let aligned_len = Crypto::aligned_len(protected_data_len);
        let encrypted_buf_start = writer.position() as usize;
        writer.write(vec![0u8;aligned_len].as_slice())?;
        let (_, encryption_buf) = writer.get_mut().as_mut_slice().split_at_mut(encrypted_buf_start);

        crypto.encrypt(iv, buf.into_inner().as_slice(), &mut encryption_buf[..]).map_err(WriteError::Encrypt)?;
        Ok(protected_data_len as u64)
    }

    fn sign(writer: &mut Cursor<Vec<u8>>, crypto: &Crypto) -> Result<(), WriteError> {
        let data_size = writer.position() as usize;
        writer.write(vec![0u8;32].as_slice())?;
        let (data, signature) = writer.get_mut().as_mut_slice().split_at_mut(data_size);
        crypto.sign(data, signature);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SimpleHeader {
    pub pkt_type: packet::Type,
    pub unprotected_payload_length: u16,
    pub protected_payload_length: u16, // This is only sometimes here!
    pub version: u16
}

impl SimpleHeader {
    fn new(pkt_type: packet::Type, version: u16) -> Result<Self, protocol::Error> {
        Ok(SimpleHeader {
            pkt_type: pkt_type,
            unprotected_payload_length: 0,
            protected_payload_length: 0,
            version: version
        })
    }
}

impl Parcel for SimpleHeader {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        let pkt_type = packet::Type::read(read)?;

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

// Placeholder
#[derive(Debug, Clone)]
pub struct MessageHeader {
    pkt_type: packet::Type,
    protected_payload_length: u16,
    unprotected_payload_length: u16,
}

impl Header for MessageHeader {
    fn set_protected_payload_length(&mut self, value: u16) {
        self.protected_payload_length = value;
    }

    fn set_unprotected_payload_length(&mut self, value: u16) {
        self.unprotected_payload_length = value;
    }
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
    extern crate nom;

    use self::nom::*;
    use super::*;
    use std::string;
    use std::io::{Cursor, Write};

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

        assert_eq!(data.to_vec(), packet.raw_bytes(&SGState::Disconnected).unwrap());
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
        let crypto = ::sgcrypto::test::from_secret(include_bytes!("test/secret"));
        let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
        let sgstate = SGState::Connected(state);
        let packet = Packet::read(data, &sgstate).unwrap();

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

    #[test]
    fn repack_connect_response_works() {
        let data = include_bytes!("test/connect_response");
        let crypto = sgcrypto::test::from_secret(include_bytes!("test/secret"));
        let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
        let sgstate = SGState::Connected(state);
        let packet = Packet::read(data, &sgstate).unwrap();

        assert_eq!(data.to_vec(), packet.raw_bytes(&sgstate).unwrap());

    }
}
