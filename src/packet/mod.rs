extern crate protocol;

pub mod simple;
pub mod message;

use std::io;
use std::io::{Read, Write, Cursor};

use ::state::*;
use ::sgcrypto;
use ::sgcrypto::Crypto;
use ::packet::simple::*;
use ::packet::message::*;

use self::protocol::*;

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
        Type(pkt_type: Type) { }

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
        Type(pkt_type: Type) { }
        Write(err: protocol::Error) { from() }
    }
}

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Type {
    ConnectRequest = 0xCC00,
    ConnectResponse = 0xCC01,
    DiscoveryRequest = 0xDD00,
    DiscoveryResponse = 0xDD01,
    PowerOnRequest = 0xDD02,
    Message = 0xD00D,
}

impl Type {
    // This could probably be a macro
    pub fn from_u16(input: u16) -> Option<Type> {
        match input {
            x if x == Type::ConnectRequest as u16 => Some(Type::ConnectRequest),
            x if x == Type::ConnectResponse as u16 => Some(Type::ConnectResponse),
            x if x == Type::DiscoveryRequest as u16 => Some(Type::DiscoveryRequest),
            x if x == Type::DiscoveryResponse as u16 => Some(Type::DiscoveryResponse),
            x if x == Type::PowerOnRequest as u16 => Some(Type::PowerOnRequest),
            x if x == Type::Message as u16 => Some(Type::Message),
            _ => None
        }
    }

    pub fn has_protected_data(&self) -> bool {
        match *self {
            Type::ConnectRequest |
            Type::ConnectResponse => true,
            _ => false
        }
    }
}

impl Parcel for Type {
    fn read(read: &mut Read) -> Result<Self, Error> {
        Ok(Type::from_u16(u16::read(read)?).unwrap())
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        (*self as u16).write(write)?;

        Ok(())
    }
}

#[derive(Debug)]
enum Packet {
    PowerOnRequest(SimpleHeader, PowerOnRequestData),
    DiscoveryRequest(SimpleHeader, DiscoveryRequestData),
    DiscoveryResponse(SimpleHeader, DiscoveryResponseData),
    ConnectRequest(SimpleHeader, ConnectRequestUnprotectedData, ConnectRequestProtectedData),
    ConnectResponse(SimpleHeader, ConnectResponseUnprotectedData, ConnectResponseProtectedData),
    Message(MessageHeader, Message)
}

trait Header {
    fn set_protected_payload_length(&mut self, value: u16);
    fn set_unprotected_payload_length(&mut self, value: u16);
}

impl Packet {
    fn read(input: &[u8], state: &SGState) -> Result<Self, ReadError> {
        let mut reader = Cursor::new(input);
        let pkt_type = Type::read(&mut reader)?;
        reader.set_position(0);

        match pkt_type {
            Type::PowerOnRequest |
            Type::DiscoveryRequest |
            Type::DiscoveryResponse |
            Type::ConnectRequest => {
                state.ensure_disconnected()?;
                Packet::read_simple(&mut reader, &state)
            }
            Type::ConnectResponse => {
                let internal_state = state.ensure_connected()?;
                let data_len = input.len() - 32;
                internal_state.crypto.verify(&input[..data_len], &input[data_len..]).map_err(ReadError::Signature)?;
                Packet::read_simple(&mut reader, &state)
            }
            Type::Message => {
                let internal_state = state.ensure_connected()?;
                let data_len = input.len() - 32;
                internal_state.crypto.verify(&input[..data_len], &input[data_len..]).map_err(ReadError::Signature)?;
                Packet::read_message(&mut reader, &state)
            }
        }
    }

    fn read_simple(reader: &mut Read, state: &SGState) -> Result<Self, ReadError> {
        let header = SimpleHeader::read(reader)?;
        match header.pkt_type {
            Type::PowerOnRequest => {
                Ok(Packet::PowerOnRequest(
                    header,
                    PowerOnRequestData::read(reader)?
                ))
            },
            Type::DiscoveryRequest => {
                Ok(Packet::DiscoveryRequest(
                    header,
                    DiscoveryRequestData::read(reader)?
                ))
            },
            Type::DiscoveryResponse => {
                Ok(Packet::DiscoveryResponse(
                    header,
                    DiscoveryResponseData::read(reader)?
                ))
            },
            Type::ConnectRequest => {
                Err(ReadError::NotImplimented)
            },
            Type::ConnectResponse => {
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

    fn read_message(reader: &mut Read, state: &SGState) -> Result<Self, ReadError> {
        let header = MessageHeader::read(reader)?;

        // todo: implement
        match header.flags.msg_type {
            _ => Ok(Packet::Message(header, Message::Null))
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
