use crate::dhcp::*;
use crate::dhcp_options::*;
use nom::bytes::complete::take;
use nom::combinator::verify;
use nom::multi::many0;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::{do_parse, take, IResult};
use std::net::Ipv4Addr;

/// Parse a DHCP message
pub fn parse_dhcp_message(i: &[u8]) -> IResult<&[u8], DHCPMessage> {
    do_parse! {
        i,
        op: be_u8 >>
        htype: be_u8 >>
        hlen: be_u8 >>
        hops: be_u8 >>
        xid: be_u32 >>
        secs: be_u16 >>
        flags: be_u16 >>
        ciaddr: parse_addr_v4 >>
        yiaddr: parse_addr_v4 >>
        siaddr: parse_addr_v4 >>
        giaddr: parse_addr_v4 >>
        chaddr: take!(16) >>
        sname: take!(64) >>
        file: take!(128) >>
        // options
        magic: take!(4) >>
        options: parse_options >>
        // padding
        _padding: parse_padding >>
        (
            DHCPMessage{
                op,
                htype,
                hlen,
                hops,
                xid,
                secs,
                flags,
                ciaddr,
                yiaddr,
                siaddr,
                giaddr,
                chaddr: chaddr.to_owned(),
                sname,
                file,
                magic: magic.to_owned(),
                options,
            }
        )
    }
}

fn parse_addr_v4(i: &[u8]) -> IResult<&[u8], Ipv4Addr> {
    let (i1, val) = take(4usize)(i)?;
    let addr = Ipv4Addr::new(val[0], val[1], val[2], val[3]);
    Ok((i1, addr))
}

fn parse_padding(i: &[u8]) -> IResult<&[u8], ()> {
    // inside many0, we don't want to fail is there are no more bytes
    use nom::bytes::complete::tag;
    let (rem, _) = many0(tag(b"\x00"))(i)?;
    Ok((rem, ()))
}

// Subnet Mask (0)
fn parse_subnet_mask_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 1)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 4)(i1)?;
    let (i3, addr) = parse_addr_v4(i2)?;
    Ok((i3, DHCPOption::SubnetMask(addr)))
}

// Requested IP Address (50)
fn parse_requested_ip_address_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 50)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 4)(i1)?;
    let (i3, addr) = parse_addr_v4(i2)?;
    Ok((i3, DHCPOption::RequestedIPAddress(addr)))
}

// IP Address Lease Time (51)
fn parse_address_lease_time_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 51)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 4)(i1)?;
    let (i3, val) = be_u32(i2)?;
    Ok((i3, DHCPOption::AddressLeaseTime(val)))
}

// Option Overload (52)
fn parse_option_overload_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 52)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 1)(i1)?;
    let (i3, val) = be_u8(i2)?;
    Ok((i3, DHCPOption::OptionOverload(val)))
}

// Message Type (53)
fn parse_message_type_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 53)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 1)(i1)?;
    let (i3, val) = be_u8(i2)?;
    Ok((i3, DHCPOption::MessageType(DHCPMessageType(val))))
}

// Parameter Request List (55)
fn parse_parameter_request_list_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 55)(i)?;
    let (i2, len) = verify(be_u8, |x| *x > 0)(i1)?;
    let (i3, val) = take(len)(i2)?;
    Ok((
        i3,
        DHCPOption::ParameterRequestList(DHCPParameterRequest(val)),
    ))
}

// Message (56)
fn parse_message_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 56)(i)?;
    let (i2, len) = verify(be_u8, |x| *x > 0)(i1)?;
    let (i3, val) = take(len)(i2)?;
    Ok((i3, DHCPOption::Message(val)))
}

// Maximum DHCP Message Size (57)
fn parse_maximum_message_size_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 57)(i)?;
    let (i2, _) = verify(be_u8, |x| *x == 2)(i1)?;
    let (i3, val) = be_u16(i2)?;
    Ok((i3, DHCPOption::MaximumSize(val)))
}

// Client Identifier (61)
fn parse_client_identifier_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    let (i1, _) = verify(be_u8, |x| *x == 61)(i)?;
    let (i2, len) = verify(be_u8, |x| *x >= 2)(i1)?;
    let (i3, val) = take(len)(i2)?;
    Ok((i3, DHCPOption::ClientIdentifier(val)))
}

fn parse_generic_option(i: &[u8]) -> IResult<&[u8], DHCPOption> {
    do_parse! {
        i,
        t: be_u8 >>
        l: be_u8 >>
        v: take!(l) >>
        (
            DHCPOption::Generic(DHCPGenericOption{ t, l, v: v.to_owned() })
        )
    }
}

fn parse_options(i: &[u8]) -> IResult<&[u8], Vec<DHCPOption>> {
    let mut acc = Vec::new();
    let mut i = i;
    loop {
        let (i2, t) = be_u8(i)?; // no need to peek, we keep i
        let (rem, opt) = match t {
            0 => (i2, DHCPOption::Pad),
            1 => parse_subnet_mask_option(i)?,
            50 => parse_requested_ip_address_option(i)?,
            51 => parse_address_lease_time_option(i)?,
            52 => parse_option_overload_option(i)?,
            53 => parse_message_type_option(i)?,
            55 => parse_parameter_request_list_option(i)?,
            56 => parse_message_option(i)?,
            57 => parse_maximum_message_size_option(i)?,
            61 => parse_client_identifier_option(i)?,
            0xff => {
                acc.push(DHCPOption::End);
                return Ok((i2, acc));
            }
            _ => parse_generic_option(i)?,
        };
        acc.push(opt);
        i = rem;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static DHCP_DISCOVER: &'static [u8] = include_bytes!("../assets/dhcp-discover.bin");
    #[test]
    fn parse_discover() {
        let res = parse_dhcp_message(DHCP_DISCOVER);
        println!("res {:?}", res);
        let (_, msg) = res.expect("Parsed message");
        println!("sname: {:?}", msg.server_name());
    }
}
