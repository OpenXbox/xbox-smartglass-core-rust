extern crate nom;

use ::util::{SGString, UUID};
use ::packet;
use self::nom::*;

/// Parses a simple message
///
/// # Arguments
/// * `input` - The input to be parsed
/// * `parse_header` - A function that can parse a header into type HT
/// * `parse_unprotected` - A function that can parse the unprotected payload into type UT
///
/// # Notes:
/// This is pretty garbage. It returns a tuple of (header, message) when it really shoudl be some sort of struct
/// It also doesn't even attempt to parse a protected payload
pub fn parse_simple_message<H, U, HT, UT>(input: &[u8], parse_header: H, parse_unprotected: U) -> IResult<&[u8], (HT, UT)>
    where H: Fn(&[u8]) -> IResult<&[u8], HT>,
          U: Fn(&[u8]) -> IResult<&[u8], UT>,
{
    do_parse!(input,
        header: parse_header >>
        unprotected: parse_unprotected >>
        (
            (header, unprotected)
        )
    )
}

pub struct Header {
    pub pkt_type: packet::Type,
    pub unprotected_payload_length: u16,
    pub protected_payload_length: u16, // This is only sometimes here!
    pub version: u16
}

impl Header {
    pub fn parse(input: &[u8]) -> IResult<&[u8], Header> {
        do_parse!(input,
            packet_type: map_opt!(u16!(Endianness::Big), packet::Type::from_u16) >>
            unprotected_payload_length: be_u16 >>
            protected_payload_length: cond!(packet_type.has_protected_data(), u16!(Endianness::Big)) >>
            version: be_u16 >>
            (
                Header {
                    pkt_type: packet_type,
                    unprotected_payload_length,
                    protected_payload_length: match protected_payload_length { Some(len) => len, None => 0 },
                    version
                }
            )
        )
    }
}

// power_request = 'power_request' / Struct(
//     'liveid' / SGString('utf8')
// ) / StructObj


pub struct DiscoveryRequest {
    unk: u16,
    client_type: u32,
    flags: u32
}

impl DiscoveryRequest {
    pub fn parse(input: &[u8]) -> IResult<&[u8], DiscoveryRequest> {
        do_parse!(input,
            unk: be_u16 >>
            client_type: be_u32 >>
            flags: be_u32 >>
            (
                DiscoveryRequest {
                    unk,
                    client_type,
                    flags
                }
            )
        )
    }
}

pub struct DiscoveryResponse {
    flags: u32,
    client_type: u16,
    name: SGString,
    uuid: UUID,
}

impl DiscoveryResponse {
    pub fn parse(input: &[u8]) -> IResult<&[u8], DiscoveryResponse> {
        do_parse!(input,
            flags: be_u32 >>
            client_type: be_u16 >>
            name: call!(SGString::parse) >>
            uuid: call!(UUID::parse) >>
            tag!(&[0u8;5][..]) >>
            (
                DiscoveryResponse {
                    flags,
                    client_type,
                    name,
                    uuid
                }
            )
        )
    }
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_discovery_request_works() {
        let data = include_bytes!("test/discovery_request");
        let result = parse_simple_message(&data[..], Header::parse, DiscoveryRequest::parse);
        match result {
            IResult::Done(_, (header, message)) => {
                assert_eq!(header.pkt_type, packet::Type::DiscoveryRequest);
                assert_eq!(header.unprotected_payload_length, 10);
                assert_eq!(header.protected_payload_length, 0);
                assert_eq!(header.version, 0);

                assert_eq!(message.client_type, 8); // Android - todo: enumify
                assert_eq!(message.flags, 2);
            }
            IResult::Error(error) => panic!(error),
            IResult::Incomplete(needed) => panic!(needed)
        }
    }

    #[test]
    fn parse_discovery_response_works() {
        let data = include_bytes!("test/discovery_response");
        let result = parse_simple_message(&data[..], Header::parse, DiscoveryResponse::parse);
        match result {
            IResult::Done(_, (header, message)) => {
                assert_eq!(header.pkt_type, packet::Type::DiscoveryResponse);
                assert_eq!(header.unprotected_payload_length, 648);
                assert_eq!(header.protected_payload_length, 0);
                assert_eq!(header.version, 2);

                assert_eq!(message.name, SGString::from_str(String::from("XboxOne")));
                assert_eq!(message.uuid, UUID::from_string(String::from("DE305D54-75B4-431B-ADB2-EB6B9E546014")));

                // I didn't even attempt to handle the certificate
            }
            IResult::Error(error) => panic!("error {:?}", error),
            IResult::Incomplete(needed) => panic!("incomplete {:?}", needed)
        }
    }
}