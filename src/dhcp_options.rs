use rusticata_macros::newtype_enum;
use std::net::Ipv4Addr;

/// A DHCP Option
#[derive(Debug)]
pub enum DHCPOption<'a> {
    /// Padding (0)
    Pad,
    /// Subnet Mask (1)
    SubnetMask(Ipv4Addr),
    /// Requested IP Address (50)
    RequestedIPAddress(Ipv4Addr),
    /// IP Address Lease Time (51)
    AddressLeaseTime(u32),
    /// Option Overload (52)
    OptionOverload(u8),
    /// Message Type (53)
    MessageType(DHCPMessageType),
    /// Server Identifier (54)
    ServerIdentifier(Ipv4Addr),
    /// Parameter Request List (55)
    ParameterRequestList(DHCPParameterRequest<'a>),
    /// Message (56)
    Message(&'a [u8]),
    /// Maximum DHCP Message Size (57)
    MaximumSize(u16),
    /// Renewal (T1) Time Value (58)
    Renewal(u32),
    /// Rebinding (T2) Time Value (59)
    Rebinding(u32),
    /// Client Identifier (61)
    ClientIdentifier(&'a [u8]),
    /// Generic (unparsed) option
    Generic(DHCPGenericOption),
    /// End of options (255)
    End,
}

/// A DHCP Unknown Option
#[derive(Debug)]
pub struct DHCPGenericOption {
    /// Tag
    pub t: u8,
    /// Length
    pub l: u8,
    /// Value
    pub v: Vec<u8>,
}

// --------- helpers ------------

impl<'a> DHCPOption<'a> {
    /// Get the numeric code for the option
    pub fn tag(&self) -> u8 {
        match self {
            DHCPOption::Pad => 0,
            DHCPOption::SubnetMask(_) => 1,
            DHCPOption::RequestedIPAddress(_) => 50,
            DHCPOption::AddressLeaseTime(_) => 51,
            DHCPOption::OptionOverload(_) => 52,
            DHCPOption::MessageType(_) => 53,
            DHCPOption::ServerIdentifier(_) => 54,
            DHCPOption::ParameterRequestList(_) => 55,
            DHCPOption::Message(_) => 56,
            DHCPOption::MaximumSize(_) => 57,
            DHCPOption::Renewal(_) => 58,
            DHCPOption::Rebinding(_) => 59,
            DHCPOption::ClientIdentifier(_) => 61,
            DHCPOption::Generic(opt) => opt.t,
            DHCPOption::End => 255,
        }
    }
}

// --------- RFC 1553 ------------

/// DHCP Message Type
pub struct DHCPMessageType(pub u8);

/// Parameter Request List
#[derive(Debug)]
pub struct DHCPParameterRequest<'a>(pub &'a [u8]);

newtype_enum! {
    impl debug DHCPMessageType {
        DHCPDISCOVER = 1,
        DHCPOFFER = 2,
        DHCPREQUEST = 3,
        DHCPDECLINE = 4,
        DHCPACK = 5,
        DHCPNAK = 6,
        DHCPRELEASE = 7,
    }
}
