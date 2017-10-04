extern crate uuid;
extern crate xbox_sg;

use xbox_sg::packet;
use xbox_sg::packet::message::{MessageType, Message};
use xbox_sg::state::*;
use xbox_sg::sgcrypto;
use xbox_sg::util::*;
use uuid::Uuid;

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

#[test]
fn parse_ack_works() {
    let data = include_bytes!("data/message/acknowledge");
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    match packet {
        packet::Packet::Message(header, message) => {
            assert_eq!(header.pkt_type, packet::Type::Message);
            assert_eq!(header.protected_payload_length, 16);
            assert_eq!(header.sequence_number, 1);
            assert_eq!(header.target_participant_id, 31);
            assert_eq!(header.source_participant_id, 0);
            assert_eq!(header.flags.msg_type, MessageType::Acknowledge);
            assert_eq!(header.flags.need_ack, false);
            assert_eq!(header.flags.is_fragment, false);
            assert_eq!(header.flags.version, 2);
            assert_eq!(header.channel_id, 0x1000000000000000);

            match message {
                Message::Acknowledge(data) => {
                    assert_eq!(data.low_watermark, 0);
                    assert_eq!(data.processed_list.elements, [1]);
                    assert_eq!(data.rejected_list.elements, []);
                },
                _ => panic!("Wrong type")
            }

        },
        _ => panic!("Wrong type")
    }
}

#[test]
fn repack_ack_works() {
    let data = include_bytes!("data/message/acknowledge");
    test_repack(data);
}

#[test]
fn parse_local_join_works() {
    let data = include_bytes!("data/message/local_join");
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    match packet {
        packet::Packet::Message(header, message) => {
            assert_eq!(header.pkt_type, packet::Type::Message);
            assert_eq!(header.flags.msg_type, MessageType::LocalJoin);
            match message {
                Message::LocalJoin(data) => {
                    assert_eq!(data.device_type, 8);
                    assert_eq!(data.native_width, 600);
                    assert_eq!(data.native_height, 1024);
                    assert_eq!(data.dpi_x, 160);
                    assert_eq!(data.dpi_y, 160);
                    assert_eq!(data.device_capabilities, 0xFFFFFFFFFFFFFFFF);
                    assert_eq!(data.client_version, 133713371);
                    assert_eq!(data.os_major_version, 42);
                    assert_eq!(data.os_minor_version, 0);
                    assert_eq!(data.display_name, SGString::from_str(String::from("package.name.here")));
                },
                _ => panic!("Wrong type")
            }
        }
        _ => panic!("Wrong type")
    }
}

#[test]
fn repack_local_join_works() {
    let data = include_bytes!("data/message/local_join");
    test_repack(data);
}
