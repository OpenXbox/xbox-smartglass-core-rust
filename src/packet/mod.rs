extern crate protocol;

pub mod simple;

use std::io::{Read, Write};

use ::serialize::{Serialize};
use self::protocol::*;

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
        Ok(Type::from_u16(u16::read(read).unwrap()).unwrap())
    }

    fn write(&self, write: &mut Write) -> Result<(), Error> {
        (*self as u16).write(write);

        Ok(())
    }
}

