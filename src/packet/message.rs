use std::io::{Read, Write};

use ::packet::{Type, Header};
use ::util::{SGString, UUID};

use protocol;
use protocol::{Parcel, DynArray};
use bit_field::BitField;
use num_traits::FromPrimitive;

#[repr(u16)]
#[derive(Primitive, PartialEq, Eq, Copy, Clone, Debug)]
pub enum MessageType {
    Null = 0x0,
    Acknowledge = 0x1,
    Group = 0x2,
    LocalJoin = 0x3,
    StopActivity = 0x5,
    AuxiliaryStream = 0x19,
    ActiveSurfaceChange = 0x1a,
    Navigate = 0x1b,
    Json = 0x1c,
    Tunnel = 0x1d,
    ConsoleStatus = 0x1e,
    TitleTextConfiguration = 0x1f,
    TitleTextInput = 0x20,
    TitleTextSelection = 0x21,
    MirroringRequest = 0x22,
    TitleLaunch = 0x23,
    StartChannelRequest = 0x26,
    StartChannelResponse = 0x27,
    StopChannel = 0x28,
    System = 0x29,
    Disconnect = 0x2a,
    TitleTouch = 0x2e,
    Accelerometer = 0x2f,
    Gyrometer = 0x30,
    Inclinometer = 0x31,
    Compass = 0x32,
    Orientation = 0x33,
    PairedIdentityStateChanged = 0x36,
    Unsnap = 0x37,
    GameDvrRecord = 0x38,
    PowerOff = 0x39,
    MediaControllerRemoved = 0xf00,
    MediaCommand = 0xf01,
    MediaCommandResult = 0xf02,
    MediaState = 0xf03,
    Gamepad = 0xf0a,
    SystemTextConfiguration = 0xf2b,
    SystemTextInput = 0xf2c,
    SystemTouch = 0xf2e,
    SystemTextAcknowledge = 0xf34,
    SystemTextDone = 0xf35
}

impl Parcel for MessageType {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        Ok(MessageType::from_u16(u16::read(read)?).unwrap())
    }

    fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
        (*self as u16).write(write)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Message {
    Null,
    Acknowledge(AcknowledgeData),
    Group,
    LocalJoin(LocalJoinData),
    StopActivity,
    AuxiliaryStream(AuxiliaryStreamData),
    ActiveSurfaceChange(ActiveSurfaceChangeData),
    Navigate,
    Json(JsonData),
    Tunnel,
    ConsoleStatus(ConsoleStatusData),
    TitleTextConfiguration(TextConfigurationData),
    TitleTextInput(TitleTextInputData),
    TitleTextSelection(TitleTextSelectionData),
    MirroringRequest,
    TitleLaunch(TitleLaunchData),
    StartChannelRequest(StartChannelRequestData),
    StartChannelResponse(StartChannelResponseData),
    StopChannel(StopChannelData),
    System,
    Disconnect(DisconnectData),
    TitleTouch(TouchData),
    Accelerometer(AccelerometerData),
    Gyrometer(GyrometerData),
    Inclinometer(InclinometerData),
    Compass(CompassData),
    Orientation(OrientationData),
    PairedIdentityStateChanged(PairedIdentityStateChangedData),
    Unsnap(UnsnapData),
    GameDvrRecord(GameDvrRecordData),
    PowerOff(PowerOffData),
    MediaControllerRemoved(MediaControllerRemovedData),
    MediaCommand(MediaCommandData),
    MediaCommandResult(MediaCommandResultData),
    MediaState(MediaStateData),
    Gamepad(GamepadData),
    SystemTextConfiguration(TextConfigurationData),
    SystemTextInput(SystemTextInputData),
    SystemTouch(TouchData),
    SystemTextAcknowledge(SystemTextAcknowledgeData),
    SystemTextDone(SystemTextDoneData)
}

impl Parcel for Message {
        fn read(read: &mut Read) -> Result<Self, protocol::Error> {
            Err(protocol::Error::from_kind(protocol::ErrorKind::UnknownPacketId))
        }

        fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
            match *self {
                Message::Acknowledge(ref data) => data.write(write),
                Message::LocalJoin(ref data) => data.write(write),
                Message::AuxiliaryStream(ref data) => data.write(write),
                Message::ActiveSurfaceChange(ref data) => data.write(write),
                Message::ConsoleStatus(ref data) => data.write(write),
                Message::TitleTextConfiguration(ref data) => data.write(write),
                Message::TitleTextInput(ref data) => data.write(write),
                Message::TitleTextSelection(ref data) => data.write(write),
                Message::TitleLaunch(ref data) => data.write(write),
                Message::StartChannelRequest(ref data) => data.write(write),
                Message::StartChannelResponse(ref data) => data.write(write),
                Message::StopChannel(ref data) => data.write(write),
                Message::Disconnect(ref data) => data.write(write),
                Message::TitleTouch(ref data) => data.write(write),
                Message::Accelerometer(ref data) => data.write(write),
                Message::Gyrometer(ref data) => data.write(write),
                Message::Inclinometer(ref data) => data.write(write),
                Message::Compass(ref data) => data.write(write),
                Message::Orientation(ref data) => data.write(write),
                Message::PairedIdentityStateChanged(ref data) => data.write(write),
                Message::Unsnap(ref data) => data.write(write),
                Message::GameDvrRecord(ref data) => data.write(write),
                Message::PowerOff(ref data) => data.write(write),
                Message::MediaControllerRemoved(ref data) => data.write(write),
                Message::MediaCommand(ref data) => data.write(write),
                Message::MediaCommandResult(ref data) => data.write(write),
                Message::MediaState(ref data) => data.write(write),
                Message::Gamepad(ref data) => data.write(write),
                Message::SystemTextConfiguration(ref data) => data.write(write),
                Message::SystemTextInput(ref data) => data.write(write),
                Message::SystemTouch(ref data) => data.write(write),
                Message::SystemTextAcknowledge(ref data) => data.write(write),
                Message::SystemTextDone(ref data) => data.write(write),
                Message::Json(ref data) => data.write(write),

                _ => Err(protocol::Error::from_kind(protocol::ErrorKind::UnknownPacketId))

            }
        }
}

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
    pub msg_type: MessageType,
    pub need_ack: bool,
    pub is_fragment: bool,
    pub version: u16
}

impl Parcel for MessageHeaderFlags {
    fn read(read: &mut Read) -> Result<Self, protocol::Error> {
        let flags = u16::read(read)?;

        Ok(MessageHeaderFlags {
            msg_type: MessageType::from_u16(flags.get_bits(0..12)).unwrap(),  // todo: enumify
            need_ack: flags.get_bit(13),
            is_fragment: flags.get_bit(14),
            version: flags.get_bits(14..16)
        })
    }

    fn write(&self, write: &mut Write) -> Result<(), protocol::Error> {
        let mut data = 0 as u16;

        data.set_bits(0..12, (self.msg_type as u16).get_bits(0..12));
        data.set_bit(13, self.need_ack);
        data.set_bit(14, self.is_fragment);
        data.set_bits(14..16, self.version.get_bits(0..2));

        data.write(write)?;

        Ok(())
    }
}

// fragment = 'fragment' / Struct(
//     'sequence_begin' / Int32ub,
//     'sequence_end' / Int32ub,
//     'data' / SGString()
// ) / StructObj

define_packet!(FragmentData {
    sequence_begin: u32,
    sequence_end: u32,
    data: DynArray<u16, u8>
});

// acknowledge = 'acknowledge' / Struct(
//     'low_watermark' / Int32ub,
//     'processed_list' / PrefixedArray(Int32ub, Int32ub),
//     'rejected_list' / PrefixedArray(Int32ub, Int32ub)
// ) / StructObj

define_packet!(AcknowledgeData {
    low_watermark: u32,
    processed_list: DynArray<u32, u32>,
    rejected_list: DynArray<u32, u32>
});

// local_join = 'local_join' / Struct(
//     'device_type' / Int16ub,
//     'native_width' / Int16ub,
//     'native_height' / Int16ub,
//     'dpi_x' / Int16ub,
//     'dpi_y' / Int16ub,
//     'device_capabilities' / Int64ub,
//     'client_version' / Int32ub,
//     'os_major_version' / Int32ub,
//     'os_minor_version' / Int32ub,
//     'display_name' / SGString('utf8')
// ) / StructObj

define_packet!(LocalJoinData {
    device_type: u16,
    native_width: u16,
    native_height: u16,
    dpi_x: u16,
    dpi_y: u16,
    device_capabilities: u64,
    client_version: u32,
    os_major_version: u32,
    os_minor_version: u32,
    display_name: SGString
});

// auxiliary_stream = 'auxiliary_stream' / Struct(
//     'connection_info_flag' / Bytes(1),
//     'crypto_key' / Bytes(0x10),
//     'server_iv' / Bytes(0x10),
//     'client_iv' / Bytes(0x10),
//     'sign_hash' / Bytes(0x10),
//     'endpoints_size' / Int16ub,
//     'message' / SGString('utf8')
// ) / StructObj

define_packet!(AuxiliaryStreamData {
    connection_info_flag: u8,
    crypto_key: [u8; 16],
    server_iv: [u8; 16],
    client_iv: [u8; 16],
    sign_hash: [u8; 16],
    endpoints_size: u16,
    message: SGString
});

// active_surface_change = 'active_surface_change' / Struct(
//     'surface_type' / Int16ub,
//     'server_tcp_port' / Int16ub,
//     'server_udp_port' / Int16ub,
//     'session_id' / UUIDAdapter(),
//     'render_width' / Int16ub,
//     'render_height' / Int16ub,
//     'master_session_key' / Bytes(0x10)
// ) / StructObj

define_packet!(ActiveSurfaceChangeData {
    surface_type: u16,
    server_tcp_port: u16,
    server_udp_port: u16,
    session_id: UUID<u8>,
    render_width: u16,
    render_height: u16,
    master_session_key: [u8; 16]
});

// json = 'json' / Struct(
//     'text' / JsonAdapter(SGString('utf8'))
// ) / StructObj

define_packet!(JsonData {
    text: SGString
});

// _active_title = '_active_title' / Struct(
//     'title_id' / Int32ub,
//     'title_disposition' / Int16ub,
//     'product_id' / UUIDAdapter(),
//     'sandbox_id' / UUIDAdapter(),
//     'aum' / SGString('utf8')
// ) / StructObj


// console_status = 'console_status' / Struct(
//     'live_tv_provider' / Int32ub,
//     'major_version' / Int32ub,
//     'minor_version' / Int32ub,
//     'build_number' / Int32ub,
//     'locale' / SGString('utf8'),
//     'active_titles' / PrefixedArray(Int16ub, _active_title)
// ) / StructObj

define_packet!(ConsoleStatusData {
    live_tv_provider: u32,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    locale: SGString,
    active_titles: DynArray<u16, ActiveTitle>
});

define_composite_type!(ActiveTitle {
    title_id: u32,
    title_disposition: u16,
    product_id: UUID<u8>,
    sandbox_id: UUID<u8>,
    aum: SGString
});

// text_configuration = 'text_configuration' / Struct(
//     'text_session_id' / Int64ub,
//     'text_buffer_version' / Int32ub,
//     'text_options' / Int32ub,
//     'input_scope' / Int32ub,
//     'max_text_length' / Int32ub,
//     'locale' / SGString('utf8'),
//     'prompt' / SGString('utf8')
// ) / StructObj

define_packet!(TextConfigurationData {
    session_id: u64,
    buffer_version: u32,
    options: u32,
    input_scope: u32,
    max_text_len: u32,
    locale: SGString,
    prompt: SGString
});

// title_text_input = 'title_text_input' / Struct(
//     'text_session_id' / Int64ub,
//     'text_buffer_version' / Int32ub,
//     'result' / Int16ub,
//     'text' / SGString('utf8')
// ) / StructObj

define_packet!(TitleTextInputData {
    session_id: u64,
    buffer_version: u32,
    result: u16,
    text: SGString
});

// title_text_selection = 'title_text_selection' / Struct(
//     'text_session_id' / Int64ub,
//     'text_buffer_version' / Int32ub,
//     'start' / Int32ub,
//     'length' / Int32ub
// ) / StructObj

define_packet!(TitleTextSelectionData {
    session_id: u64,
    buffer_version: u32,
    start: u32,
    length: u32
});

// title_launch = 'title_launch' / Struct(
//     'location' / Int16ub,
//     'uri' / SGString()
// ) / StructObj

define_packet!(TitleLaunchData {
    location: u16,
    uri: SGString
});

// start_channel_request = 'start_channel_request' / Struct(
//     'channel_request_id' / Int32ub,
//     'title_id' / Int32ub,
//     'service' / UUIDAdapter(),
//     'activity_id' / Int32ub
// ) / StructObj

define_packet!(StartChannelRequestData {
    channel_request_id: u32,
    title_id: u32,
    service: UUID<u8>,
    activity_id: u32
});

// start_channel_response = 'start_channel_response' / Struct(
//     'channel_request_id' / Int32ub,
//     'target_channel_id' / Int64ub,
//     'result' / Int32ub
// ) / StructObj

define_packet!(StartChannelResponseData {
    channel_request_id: u32,
    target_channel_id: u64,
    result: u32
});

// stop_channel = 'stop_channel' / Struct(
//     'target_channel_id' / Int64ub
// ) / StructObj

define_packet!(StopChannelData {
    target_channel_id: u64
});

// disconnect = 'disconnect' / Struct(
//     'reason' / Int32ub,
//     'error_code' / Int32ub
// ) / StructObj

define_packet!(DisconnectData {
    reason: u32,
    error_code: u32
});

// _touchpoint = '_touchpoint' / Struct(
//     'touchpoint_id' / Int32ub,
//     'touchpoint_action' / Int16ub,
//     'touchpoint_x' / Int32ub,
//     'touchpoint_y' / Int32ub
// ) / StructObj


// touch = 'touch' / Struct(
//     'touch_msg_timestamp' / Int32ub,
//     'active_titles' / PrefixedArray(Int16ub, _touchpoint)
// ) / StructObj

define_packet!(TouchData {
    timestamp: u32,
    active_titles: DynArray<u16, Touchpoint>
});

define_composite_type!(Touchpoint {
    id: u32,
    action: u16,
    x: u32,
    y: u32
});

// accelerometer = 'accelerometer' / Struct(
//     'timestamp' / Int64ub,
//     'acceleration_x' / Float32b,
//     'acceleration_y' / Float32b,
//     'acceleration_z' / Float32b
// ) / StructObj

define_packet!(AccelerometerData {
    timestamp: u64,
    acceleration_x: f32,
    acceleration_y: f32,
    acceleration_z: f32
});

// gyrometer = 'gyrometer' / Struct(
//     'timestamp' / Int64ub,
//     'angular_velocity_x' / Float32b,
//     'angular_velocity_y' / Float32b,
//     'angular_velocity_z' / Float32b
// ) / StructObj

define_packet!(GyrometerData {
    timestamp: u64,
    angular_velocity_x: f32,
    angular_velocity_y: f32,
    angular_velocity_z: f32
});

// inclinometer = 'inclinometer' / Struct(
//     'timestamp' / Int64ub,
//     'pitch' / Float32b,
//     'roll' / Float32b,
//     'yaw' / Float32b
// ) / StructObj

define_packet!(InclinometerData {
    timestamp: u64,
    pitch: f32,
    roll: f32,
    yaw: f32
});

// compass = 'compass' / Struct(
//     'timestamp' / Int64ub,
//     'magnetic_north' / Float32b,
//     'true_north' / Float32b
// ) / StructObj

define_packet!(CompassData {
    timestamp: u64,
    magnetic_north: f32,
    true_north: f32
});

// orientation = 'orientation' / Struct(
//     'timestamp' / Int64ub,
//     'rotation_matrix_value' / Float32b,
//     'w' / Float32b,
//     'x' / Float32b,
//     'y' / Float32b,
//     'z' / Float32b
// ) / StructObj

define_packet!(OrientationData {
    timestamp: u64,
    rotation_matrix_value: u64,
    w: f32,
    x: f32,
    y: f32,
    z: f32
});

// paired_identity_state_changed = 'paired_identity_state_changed' / Struct(
//     'state' / Int16ub
// ) / StructObj

define_packet!(PairedIdentityStateChangedData {
    state: u16  // todo: enumify
});

// unsnap = 'unsnap' / Struct(
//     'unk' / Bytes(1)
// ) / StructObj

define_packet!(UnsnapData {
    unk: u8
});

// game_dvr_record = 'game_dvr_record' / Struct(
//     'start_time_delta' / Int32ub,
//     'end_time_delta' / Int32ub
// ) / StructObj

define_packet!(GameDvrRecordData {
    start_time_delta: u32,
    end_time_delta: u32
});

// power_off = 'power_off' / Struct(
//     'device_id' / SGString('utf8')
// ) / StructObj

define_packet!(PowerOffData {
    device_id: SGString
});

// media_controller_removed = 'media_controller_removed' / Struct(
//     'title_id' / Int32ub
// ) / StructObj

define_packet!(MediaControllerRemovedData {
    title_id: u32
});

// media_command = 'media_command' / Struct(
//     'request_id' / Int64ub,
//     'title_id' / Int32ub,
//     'command' / Int32ub,
//     'seek_position' / If(this.command == MediaControlCommand.Seek, Int64ub)
// ) / StructObj

define_packet!(MediaCommandData {
    request_id: u64,
    title_id: u32,
    command: u32  // todo: enumify
    // todo add seek_position
});

// media_command_result = 'media_command_result' / Struct(
//     'request_id' / Int64ub,
//     'result' / Int32ub
// ) / StructObj

define_packet!(MediaCommandResultData {
    request_id: u64,
    result: u32
});

// media_state = 'media_state' / Struct(
//     'title_id' / Int32ub,
//     'aum_id' / SGString('utf8'),
//     'asset_id' / SGString('utf8'),
//     'media_type' / Int16ub,
//     'sound_level' / Int16ub,
//     'enabled_commands' / Int32ub,
//     'playback_status' / Int16ub,
//     'rate' / Float32b,
//     'position' / Int64ub,
//     'media_start' / Int64ub,
//     'media_end' / Int64ub,
//     'min_seek' / Int64ub,
//     'max_seek' / Int64ub,
//     'metadata' / PrefixedArray(Int16ub, Struct(
//         'name' / SGString('utf8'),
//         'value' / SGString('utf8')
//     ))
// ) / StructObj

define_packet!(MediaStateData {
    title_id: u32,
    aum_id: SGString,
    asset_id: SGString,
    media_type: u16,
    sound_level: u16,
    enabled_commands: u32,
    playback_status: u16,
    rate: f32,
    position: u64,
    media_start: u64,
    media_end: u64,
    min_seek: u64,
    max_seek: u64,
    metadata: DynArray<u16, MediaStateMetadata>
});

define_composite_type!(MediaStateMetadata {
    name: SGString,
    value: SGString
});

// gamepad = 'gamepad' / Struct(
//     'timestamp' / Int64ub,
//     'buttons' / Int16ub,
//     'left_trigger' / Float32b,
//     'right_trigger' / Float32b,
//     'left_thumbstick_x' / Float32b,
//     'left_thumbstick_y' / Float32b,
//     'right_thumbstick_x' / Float32b,
//     'right_thumbstick_y' / Float32b
// ) / StructObj

define_packet!(GamepadData {
    timestamp: u64,
    buttons: u16,  // todo: bitfield or something
    left_trigger: f32,
    right_trigger: f32,
    left_thumbstick_x: f32,
    left_thumbstick_y: f32,
    right_thumbstick_x: f32,
    right_thumbstick_y: f32
});

// system_text_input = 'system_text_input' / Struct(
//     'text_session_id' / Int32ub,
//     'base_version' / Int32ub,
//     'submitted_version' / Int32ub,
//     'total_text_byte_len' / Int32ub,
//     'selection_start' / Int32ub,
//     'selection_length' / Int32ub,
//     'flags' / Int16ub,
//     'text_chunk_byte_start' / Int32ub,
//     'delta' / Pass,  # TODO: some variable copying magic, has a Int16ub length field
//     'text_chunk' / SGString('utf8')
// ) / StructObj

define_packet!(SystemTextInputData {
    session_id: u32,
    base_version: u32,
    submitted_version: u32,
    total_text_byte_len: u32,
    selection_start: u32,
    selection_len: u32,
    flags: u16,
    text_chunk_byte_start: u32,
    text_chunk: SGString
});

// system_text_acknowledge = 'system_text_acknowledge' / Struct(
//     'text_session_id' / Int32ub,
//     'text_version_ack' / Int32ub
// ) / StructObj

define_packet!(SystemTextAcknowledgeData {
    session_id: u32,
    version_ack: u32
});

// system_text_done = 'system_text_done' / Struct(
//     'text_session_id' / Int32ub,
//     'text_version' / Int32ub,
//     'flags' / Int32ub,
//     'unk' / Int32ub
// ) / StructObj

define_packet!(SystemTextDoneData {
    session_id: u32,
    version: u32,
    flags: u32,
    unk: u32
});
