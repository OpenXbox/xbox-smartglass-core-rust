extern crate xbox_sg;
extern crate protocol;

use xbox_sg::packet;
use xbox_sg::packet::message::{Message, MessageHeader, MessageHeaderFlags, MessageType};
use xbox_sg::state::*;
use xbox_sg::sgcrypto;
use xbox_sg::util::*;
use protocol::DynArray;

fn new_connected_state() -> SGState {
    let crypto = sgcrypto::tests::from_secret(include_bytes!("data/secret"));
    let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
    SGState::Connected(state)
}

fn test_repack(data: &[u8]) {
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    assert_eq!(data.to_vec(), packet.raw_bytes(&sgstate).unwrap());
}

fn test_message(data: &[u8], message: Message, header: MessageHeader) {
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    match packet {
        packet::Packet::Message(parsed_header, parsed_message) => {
            assert_eq!(parsed_header, header);
            assert_eq!(parsed_message, message);
        },
        _ => panic!("Wrong type")
    }
}

#[test]
fn parse_ack_works() {
    let data = include_bytes!("data/message/acknowledge");
    
    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::Acknowledge,
        need_ack: false,
        is_fragment: false,
        version: 2
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 16,
        sequence_number: 1,
        target_participant_id: 31,
        source_participant_id: 0,
        flags: header_flags,
        channel_id: 0x1000000000000000
    };

    let message = packet::message::AcknowledgeData {
        low_watermark: 0,
        processed_list: DynArray::new(vec![1]),
        rejected_list: DynArray::new(vec![])
    };

    test_message(data, Message::Acknowledge(message), header);
}

#[test]
fn repack_ack_works() {
    let data = include_bytes!("data/message/acknowledge");
    test_repack(data);
}

#[test]
fn parse_local_join_works() {
    let data = include_bytes!("data/message/local_join");
    
    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::LocalJoin,
        need_ack: true,
        is_fragment: false,
        version: 0
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 50,
        sequence_number: 1,
        target_participant_id: 0,
        source_participant_id: 31,
        flags: header_flags,
        channel_id: 0
    };

    let message = packet::message::LocalJoinData {
        device_type: 8,
        native_width: 600,
        native_height: 1024,
        dpi_x: 160,
        dpi_y: 160,
        device_capabilities: 0xFFFFFFFFFFFFFFFF,
        client_version: 133713371,
        os_major_version: 42,
        os_minor_version: 0,
        display_name: SGString::from_str(String::from("package.name.here")),
    };

    test_message(data, Message::LocalJoin(message), header);
}

#[test]
fn repack_local_join_works() {
    let data = include_bytes!("data/message/local_join");
    test_repack(data);
}