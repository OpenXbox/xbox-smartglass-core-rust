extern crate uuid;

use self::uuid::Uuid;

use ::packet::*;
use ::packet::simple::*;
use ::packet::message::*;
use ::util::{SGString, PublicKey, UUID};

use std::string::String;

pub fn power_on_request(live_id: String) -> Packet {
    let header = SimpleHeader::new(Type::PowerOnRequest, 2);
    let data = PowerOnRequestData {
        live_id: SGString::from_str(live_id)
    };

    Packet::PowerOnRequest(header, data)
}

pub fn discovery_request(client_type: u32) -> Packet {
    let header = SimpleHeader::new(Type::DiscoveryRequest, 0);
    let data = DiscoveryRequestData {
        unk: 0,
        client_type,
        flags: 2
    };

    Packet::DiscoveryRequest(header, data)
}

pub fn connect_request(sg_uuid: Uuid, public_key: PublicKey, iv: [u8; 16], userhash: String, jwt: String, request_num: u32, request_group_start: u32, request_group_end: u32) -> Packet {
    let header = SimpleHeader::new(Type::ConnectRequest, 2);
    let unprotected_data = ConnectRequestUnprotectedData {
        sg_uuid: UUID::new(sg_uuid),
        public_key,
        iv
    };
    let protected_data = ConnectRequestProtectedData {
        userhash: SGString::from_str(userhash),
        jwt: SGString::from_str(jwt),
        request_num,
        request_group_start,
        request_group_end
    };

    Packet::ConnectRequest(header, unprotected_data, protected_data)
}
