use ::sgcrypto::Crypto;

quick_error!{
    #[derive(Debug)]
    pub enum InvalidState {
        Connected {
            display("Invalid state: connected")
        }
        Disconnected {
            display("Invalid state: disconnected")
        }
    }
}

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

impl SGState {
    pub fn ensure_connected(&self) -> Result<&State, InvalidState> {
        match *self {
            SGState::Disconnected => Err(InvalidState::Disconnected),
            SGState::Connected(ref state) => Ok(state)
        }
    }

    pub fn ensure_disconnected(&self) -> Result<(), InvalidState> {
        match *self {
            SGState::Disconnected => Ok(()),
            SGState::Connected(_) => Err(InvalidState::Connected)
        }
    }
}


