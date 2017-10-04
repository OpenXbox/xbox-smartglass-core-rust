extern crate uuid;
extern crate xbox_sg;

use xbox_sg::packet;
use xbox_sg::state::*;
use xbox_sg::sgcrypto;
use xbox_sg::util::*;
use uuid::Uuid;

fn new_connected_state() -> SGState {
    let crypto = sgcrypto::tests::from_secret(include_bytes!("data/secret"));
    let state = State{ connection_state: ConnectionState::Connecting, pairing_state: PairingState::NotPaired, crypto };
    SGState::Connected(state)
}

#[test]
fn parse_discovery_request_works() {
    let data = include_bytes!("data/discovery_request");
    let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

    match packet {
        packet::Packet::DiscoveryRequest(header, data) => {
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
    let data = include_bytes!("data/discovery_request");
    let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

    assert_eq!(data.to_vec(), packet.raw_bytes(&SGState::Disconnected).unwrap());
}

#[test]
fn parse_discovery_response_works() {
    let data = include_bytes!("data/discovery_response");
    let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

    match packet {
        packet::Packet::DiscoveryResponse(header, data) => {
            assert_eq!(header.pkt_type, packet::Type::DiscoveryResponse);
            assert_eq!(header.unprotected_payload_length, 648);
            assert_eq!(header.protected_payload_length, 0);
            assert_eq!(header.version, 2);;
            // Protocol crate also exports a String type, dunno how to properly handle this yet though, so this'll have to do for now
            assert_eq!(data.name, SGString::from_str(String::from("XboxOne")));
            assert_eq!(data.uuid, UUID::new(Uuid::parse_str("DE305D54-75B4-431B-ADB2-EB6B9E546014").unwrap()));
            assert_eq!(data.certificate.subject(), "FFFFFFFFFFF");
            assert_eq!(data.certificate.public_key_type(), 4);
            // assert_eq!(data.certificate.elements.len(), 587); // todo: properly parse cert
        },
        _ => panic!("Wrong type")
    }
}

#[test]
fn rebuild_discovery_response_works() {
    let data = include_bytes!("data/discovery_response");
    let packet = packet::Packet::read(data, &SGState::Disconnected).unwrap();

    assert_eq!(data.to_vec(), packet.raw_bytes(&SGState::Disconnected).unwrap());
}

// #[test]
// fn parse_connect_request_unprotected_data_works() {
//     let data = include_bytes!("data/connect_request");
//     let crypto = ::sgcrypto::test::from_secret(include_bytes!("data/secret"));
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
    let data = include_bytes!("data/connect_response");
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    match packet {
        packet::Packet::ConnectResponse(header, unprotected_data, protected_data) => {
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
    let data = include_bytes!("data/connect_response");
    let sgstate = new_connected_state();
    let packet = packet::Packet::read(data, &sgstate).unwrap();

    assert_eq!(data.to_vec(), packet.raw_bytes(&sgstate).unwrap());
}
