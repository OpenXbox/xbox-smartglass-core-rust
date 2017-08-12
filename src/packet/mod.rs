pub mod simple;

pub enum Type {
    ConnectRequest = 0xCC00,
    ConnectResponse = 0xCC01,
    DiscoveryRequest = 0xDD00,
    DiscoveryResponse = 0xDD01,
    PowerOnRequest = 0xDD02,
    Message = 0xD00D,
}