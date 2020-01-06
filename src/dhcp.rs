use crate::dhcp_options::DHCPOption;
use std::ffi::CStr;
use std::net::Ipv4Addr;

/// A DHCP Message
#[derive(Debug)]
pub struct DHCPMessage<'a> {
    /// Message op code / message type
    pub op: u8,
    /// Hardware address type
    pub htype: u8,
    /// Hardware address length
    pub hlen: u8,
    /// Client sets to zero, optionally used by relay-agents when booting via a relay-agent.
    pub hops: u8,
    /// Transaction ID
    pub xid: u32,
    /// Seconds elapsed since client started trying to boot
    pub secs: u16,
    /// Flags
    pub flags: u16,
    /// Client IP address
    pub ciaddr: Ipv4Addr,
    /// Your (client) IP address
    pub yiaddr: Ipv4Addr,
    /// IP address of next server to use in bootstrap
    pub siaddr: Ipv4Addr,
    /// Relay agent IP address
    pub giaddr: Ipv4Addr,
    /// Client hardware address
    pub chaddr: Vec<u8>,
    /// Optional server host name, null terminated string
    pub sname: &'a [u8],
    /// Boot file name, null terminated string
    pub file: &'a [u8],
    /// Magic (usually DHCP)
    pub magic: Vec<u8>,
    /// Optional parameters field
    pub options: Vec<DHCPOption<'a>>,
}

#[derive(Debug)]
pub enum MaybeStr<'a> {
    Empty,
    Str(&'a CStr),
    FromUTF8Error,
}

impl<'a> DHCPMessage<'a> {
    /// Get the server host name
    pub fn server_name(&self) -> MaybeStr<'a> {
        let last_index = self.sname.iter().position(|&b| b == 0);
        if last_index == Some(0) {
            return MaybeStr::Empty;
        }
        match CStr::from_bytes_with_nul(self.sname) {
            Ok(s) => MaybeStr::Str(s),
            Err(_) => MaybeStr::FromUTF8Error,
        }
    }

    /// Get the server host name
    pub fn file(&self) -> MaybeStr<'a> {
        let last_index = self.file.iter().position(|&b| b == 0);
        if last_index == Some(0) {
            return MaybeStr::Empty;
        }
        match CStr::from_bytes_with_nul(self.file) {
            Ok(s) => MaybeStr::Str(s),
            Err(_) => MaybeStr::FromUTF8Error,
        }
    }
}
