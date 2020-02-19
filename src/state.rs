use crate::{DHCPMessage, DHCPMessageType};

/// DHCP State Machine
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DHCPClientState {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,

    Error,
}

impl DHCPClientState {
    /// Advance to next state
    pub fn next(self, msg: &DHCPMessage) -> Self {
        use DHCPClientState::*;
        let msg_type = match msg.message_type() {
            Some(t) => t,
            None => {
                return Error;
            }
        };
        eprintln!("   MESSAGE TYPE {:?}", msg_type);
        match (self, msg_type) {
            (Error, _) => Error,
            (Init, DHCPMessageType::DHCPDISCOVER) => Selecting,
            (Selecting, DHCPMessageType::DHCPOFFER) => Selecting,
            (Selecting, DHCPMessageType::DHCPREQUEST) => Requesting,
            (Requesting, DHCPMessageType::DHCPACK) => Bound,
            (Bound, DHCPMessageType::DHCPREQUEST) => Renewing,
            (Bound, DHCPMessageType::DHCPRELEASE) => Init,
            (Renewing, DHCPMessageType::DHCPACK) => Bound,
            (Renewing, DHCPMessageType::DHCPREQUEST) => Rebinding,
            (Rebinding, DHCPMessageType::DHCPACK) => Bound,
            (Rebinding, DHCPMessageType::DHCPNAK) => Init,
            (_, _) => Error,
        }
    }
}
