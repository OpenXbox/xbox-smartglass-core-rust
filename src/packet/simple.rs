use ::util::{SGString};

struct Header {
    pkt_type: u16,
    unprotected_payload_length: u32,
    protected_payload_length: u32, // This is only sometimes here!
    version: u16
}



// power_request = 'power_request' / Struct(
//     'liveid' / SGString('utf8')
// ) / StructObj


struct DiscoveryRequest {
    unk: u16,
    clientType: u32,
    flags: u32
}

struct DiscoveryResponse {
    flags: u32,
    clientType: u16,
    name: SGString,
    uuid: [u8;16], // is this even right?

}

// discovery_request = 'discovery_request' / Struct(
//     'unk' / Int16ub,
//     'client_type' / Int32ub,
//     'flags' / Int32ub
// ) / StructObj


// discover_response = 'discovery_response' / Struct(
//     'flags' / Int32ub,
//     'type' / Int16ub,
//     'name' / SGString('utf8'),
//     'uuid' / UUIDAdapter('utf8'),
//     Padding(5),
//     'cert' / CertificateAdapter()
// ) / StructObj


// connect_request_unprotected = 'connect_request_unprotected' / Struct(
//     'sg_uuid' / UUIDAdapter(),
//     'public_key_type' / Int16ub,
//     'public_key' / Bytes(0x40),
//     'iv' / Bytes(0x10)
// ) / StructObj


// connect_request_protected = 'connect_request_protected' / Struct(
//     'userhash' / SGString('utf8'),
//     'jwt' / SGString('utf8'),
//     'connect_request_num' / Int32ub,
//     'connect_request_group_start' / Int32ub,
//     'connect_request_group_end' / Int32ub
// ) / StructObj


// connect_response_unprotected = 'connect_response_unprotected' / Struct(
//     'iv' / Bytes(0x10)
// ) / StructObj


// connect_response_protected = 'connect_response_protected' / Struct(
//     'connect_result' / Int16ub,
//     'pairing_state' / Int16ub,
//     'participant_id' / Int32ub
// ) / StructObj


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