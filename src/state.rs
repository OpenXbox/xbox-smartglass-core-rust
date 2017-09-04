use ::sgcrypto::Crypto;

pub enum ConnectionState {
    Disconnected = 0x0,
    Connecting = 0x1,
    Connected = 0x2,
    Error = 0x3,
    Disconnecting = 0x4,
    Reconnecting = 0x5
}

pub enum PairingState {
    NotPaired = 0x0,
    Paired = 0x1
}

pub struct State {
    pub connection_state: ConnectionState,
    pub pairing_state: PairingState,
    pub crypto: Crypto,
}

pub enum SGState {
    Disconnected,
    Connected(State)
}