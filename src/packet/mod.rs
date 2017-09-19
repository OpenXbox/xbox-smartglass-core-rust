pub mod simple;
pub mod message;
pub mod factory;

use std::io;
use std::io::{Read, Write, Cursor};

use ::state::*;
use ::sgcrypto;
use ::sgcrypto::Crypto;
use ::packet::simple::*;
use ::packet::message::*;

use protocol;
use protocol::{Parcel};
use num_traits::FromPrimitive;

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
        IV(err: sgcrypto::Error) { }
        Message(err: String) { from() }
        NotImplimented { }
        Signature(err: sgcrypto::Error) { }
        State(err: InvalidState) { from() }
        Type(pkt_type: Type) { }
        Write(err: protocol::Error) { from() }
    }
}

#[derive(Primitive, PartialEq, Eq, Copy, Clone, Debug)]
pub enum Type {
    ConnectRequest = 0xCC00,
    ConnectResponse = 0xCC01,
    DiscoveryRequest = 0xDD00,
    DiscoveryResponse = 0xDD01,
    PowerOnRequest = 0xDD02,
    Message = 0xD00D
}

impl Type {
    pub fn has_protected_data(&self) -> bool {
        match *self {
            Type::ConnectRequest |
            Type::ConnectResponse => true,
            _ => false
        }
    }
}

impl Parcel for Type {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        Ok(Type::from_u16(u16::read(read)?).unwrap())
    }

    fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
        (*self as u16).write(write)?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum Packet {
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
        let internal_state = state.ensure_connected()?;

        let header_buf: [u8; 26] = Parcel::read(reader)?;
        let header = MessageHeader::from_raw_bytes(&header_buf)?;

        let mut iv = [0u8; 16];
        internal_state.crypto.generate_iv(&header_buf[..16], &mut iv);
        let decrypted_buf = Packet::decrypt(reader, &internal_state.crypto, header.protected_payload_length as usize, &iv)?;

        // // todo: implement
        let message = match header.flags.msg_type {
            MessageType::Acknowledge => {
                Message::Acknowledge(
                    AcknowledgeData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::LocalJoin => {
                Message::LocalJoin(
                    LocalJoinData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::AuxiliaryStream => {
                Message::AuxiliaryStream(
                    AuxiliaryStreamData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::ActiveSurfaceChange => {
                Message::ActiveSurfaceChange(
                    ActiveSurfaceChangeData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Json => {
                Message::Json(
                        JsonData::from_raw_bytes(&decrypted_buf)?
                    )
            },
            MessageType::ConsoleStatus => {
                Message::ConsoleStatus(
                    ConsoleStatusData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::TitleTextConfiguration => {
                Message::TitleTextConfiguration(
                    TextConfigurationData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::TitleTextInput => {
                Message::TitleTextInput(
                    TitleTextInputData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::TitleTextSelection => {
                Message::TitleTextSelection(
                    TitleTextSelectionData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::TitleLaunch => {
                Message::TitleLaunch(
                    TitleLaunchData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::StartChannelRequest => {
                Message::StartChannelRequest(
                    StartChannelRequestData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::StartChannelResponse => {
                Message::StartChannelResponse(
                    StartChannelResponseData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::StopChannel => {
                Message::StopChannel(
                    StopChannelData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Disconnect => {
                Message::Disconnect(
                    DisconnectData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::TitleTouch => {
                Message::TitleTouch(
                    TouchData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Accelerometer => {
                Message::Accelerometer(
                    AccelerometerData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Gyrometer => {
                Message::Gyrometer(
                    GyrometerData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Inclinometer => {
                Message::Inclinometer(
                    InclinometerData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Compass => {
                Message::Compass(
                    CompassData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Orientation => {
                Message::Orientation(
                    OrientationData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::PairedIdentityStateChanged => {
                Message::PairedIdentityStateChanged(
                    PairedIdentityStateChangedData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Unsnap => {
                Message::Unsnap(
                    UnsnapData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::GameDvrRecord => {
                Message::GameDvrRecord(
                    GameDvrRecordData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::PowerOff => {
                Message::PowerOff(
                    PowerOffData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::MediaControllerRemoved => {
                Message::MediaControllerRemoved(
                    MediaControllerRemovedData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::MediaCommand => {
                Message::MediaCommand(
                    MediaCommandData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::MediaCommandResult => {
                Message::MediaCommandResult(
                    MediaCommandResultData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::MediaState => {
                Message::MediaState(
                    MediaStateData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::Gamepad => {
                Message::Gamepad(
                    GamepadData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::SystemTextConfiguration => {
                Message::SystemTextConfiguration(
                    TextConfigurationData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::SystemTextInput => {
                Message::SystemTextInput(
                    SystemTextInputData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::SystemTouch => {
                Message::SystemTouch(
                    TouchData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::SystemTextAcknowledge => {
                Message::SystemTextAcknowledge(
                    SystemTextAcknowledgeData::from_raw_bytes(&decrypted_buf)?
                )
            },
            MessageType::SystemTextDone => {
                Message::SystemTextDone(
                    SystemTextDoneData::from_raw_bytes(&decrypted_buf)?
                )
            }
            _ => Message::Null
        };

        Ok(Packet::Message(
            header, message
        ))
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
            Packet::Message(ref header, ref message) =>  {
                let internal_state = state.ensure_connected()?;
                Packet::write_message(write, &internal_state.crypto, header, message)?;
            }
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

    fn write_message(write: &mut Cursor<Vec<u8>>, crypto: &Crypto, header: &MessageHeader, message: &Message) -> Result<(), WriteError> {
        // Calculate Lengths
        let mut header_clone = header.clone();
        header.write(write)?;
        let header_len = write.position();
        message.write(write)?;
        let protected_len = write.position() - header_len;

        // Serialize correct header
        header_clone.set_protected_payload_length(protected_len as u16);
        write.set_position(0);
        header_clone.write(write)?;

        // Generate IV
        let mut iv = [0u8;16];
        crypto.generate_iv(&write.get_ref()[..16], &mut iv[..]).map_err(WriteError::IV)?;

        // Serialize encrypted message
        Packet::encrypt(write, message, crypto, &iv)?;

        // Sign
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
