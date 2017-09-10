extern crate protocol;
extern crate bit_field;

use std::io::{Read, Write};

use ::packet::{Type, Header};

use self::protocol::*;
use self::bit_field::BitField;

define_composite_type!(MessageHeader {
    pkt_type: Type,
    protected_payload_length: u16,
    sequence_number: u32,
    target_participant_id: u32,
    source_participant_id: u32,
    flags: MessageHeaderFlags,
    channel_id: u64
});

impl Header for MessageHeader {
    fn set_protected_payload_length(&mut self, value: u16) {
        self.protected_payload_length = value;
    }

    fn set_unprotected_payload_length(&mut self, value: u16) {
        return
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageHeaderFlags {
    msg_type: u16,
    need_ack: bool,
    is_fragment: bool,
    version: u16
}

impl Parcel for MessageHeaderFlags {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        let flags = u16::read(read)?;

        Ok(MessageHeaderFlags {
            msg_type: flags.get_bits(0..12),  // todo: enumify
            need_ack: flags.get_bit(13),
            is_fragment: flags.get_bit(14),
            version: flags.get_bits(14..16)
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
        let mut data = 0 as u16;

        data.set_bits(0..12, self.msg_type.get_bits(0..12));
        data.set_bit(13, self.need_ack);
        data.set_bit(14, self.is_fragment);
        data.set_bits(14..16, self.version.get_bits(0..2));

        data.write(write)?;

        Ok(())
    }
}
