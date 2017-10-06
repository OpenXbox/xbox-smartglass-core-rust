extern crate xbox_sg;
extern crate protocol;

use xbox_sg::packet;
use xbox_sg::packet::message::{Message, MessageHeader, MessageHeaderFlags, MessageType};
use xbox_sg::state::*;
use xbox_sg::sgcrypto;
use xbox_sg::util::*;
use xbox_sg::constants;
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

#[test]
fn parse_start_channel_request_works() {
    let data = include_bytes!("data/message/start_channel_request");

    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::StartChannelRequest,
        need_ack: true,
        is_fragment: false,
        version: 2
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 28,
        sequence_number: 2,
        target_participant_id: 0,
        source_participant_id: 31,
        flags: header_flags,
        channel_id: 0
    };

    let message = packet::message::StartChannelRequestData {
        channel_request_id: 1,
        title_id: 0,
        service: constants::uuid::SYSTEM_INPUT.clone(),
        activity_id: 0
    };

    test_message(data, Message::StartChannelRequest(message), header);
}

#[test]
fn repack_start_channel_request_works() {
    let data = include_bytes!("data/message/start_channel_request");
    test_repack(data);
}

#[test]
fn parse_start_channel_response_works() {
    let data = include_bytes!("data/message/start_channel_response");

    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::StartChannelResponse,
        need_ack: true,
        is_fragment: false,
        version: 2
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 16,
        sequence_number: 6,
        target_participant_id: 31,
        source_participant_id: 0,
        flags: header_flags,
        channel_id: 0
    };

    let message = packet::message::StartChannelResponseData {
        channel_request_id: 1,
        target_channel_id: 148,
        result: 0
    };

    test_message(data, Message::StartChannelResponse(message), header);
}

#[test]
fn repack_start_channel_response_works() {
    let data = include_bytes!("data/message/start_channel_response");
    test_repack(data);
}

#[test]
fn parse_console_status_works() {
    let data = include_bytes!("data/message/console_status");

    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::ConsoleStatus,
        need_ack: true,
        is_fragment: false,
        version: 2
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 112,
        sequence_number: 5,
        target_participant_id: 31,
        source_participant_id: 0,
        flags: header_flags,
        channel_id: 0
    };

    let message = packet::message::ConsoleStatusData {
        live_tv_provider: 0,
        major_version: 10,
        minor_version: 0,
        build_number: 14393,
        locale: SGString::from_str(String::from("en-US")),
        active_titles: DynArray::new(vec![
            packet::message::ActiveTitle {
                title_id: 714681658,
                title_disposition: 32771,
                product_id: constants::uuid::NONE.clone(),
                sandbox_id: constants::uuid::NONE.clone(),
                aum: SGString::from_str(String::from("Xbox.Home_8wekyb3d8bbwe!Xbox.Home.Application"))
            }
        ])
    };

    test_message(data, Message::ConsoleStatus(message), header);
}

#[test]
fn repack_console_status_works() {
    let data = include_bytes!("data/message/console_status");
    test_repack(data);
}

#[test]
fn parse_disconnect_works() {
    let data = include_bytes!("data/message/disconnect");

    let header_flags = MessageHeaderFlags {
        msg_type: MessageType::Disconnect,
        need_ack: false,
        is_fragment: false,
        version: 2
    };

    let header = MessageHeader {
        pkt_type: packet::Type::Message,
        protected_payload_length: 8,
        sequence_number: 57,
        target_participant_id: 0,
        source_participant_id: 31,
        flags: header_flags,
        channel_id: 0
    };

    let message = packet::message::DisconnectData {
        reason: 0,
        error_code: 0
    };

    test_message(data, Message::Disconnect(message), header);
}

#[test]
fn repack_disconnect_works() {
    let data = include_bytes!("data/message/disconnect");
    test_repack(data);
}