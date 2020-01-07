use crate::dhcp::*;
use crate::dhcp_options::*;
use nom::bytes::complete::take;
use nom::error::ErrorKind;
use nom::multi::many0;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::{do_parse, take, IResult};
use std::net::Ipv4Addr;

macro_rules! nom_err_return (
    ($i:expr, $cond:expr, $err:expr) => (
        {
            if $cond {
                return Err(::nom::Err::Error(::nom::error_position!($i, $err)));
            }
        }
    );
);

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

fn parse_generic_option(i: &[u8]) -> IResult<&[u8], DHCPGenericOption> {
    do_parse! {
        i,
        t: be_u8 >>
            l: be_u8 >>
            v: take!(l) >>
            (
                DHCPGenericOption{ t, l, v }
            )
    }
}

fn convert_generic_option<'a>(
    i: &'a [u8],
    opt: DHCPGenericOption<'a>,
) -> IResult<&'a [u8], DHCPOption<'a>> {
    let opt = match opt.t {
        1 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, addr) = parse_addr_v4(opt.v)?;
            DHCPOption::SubnetMask(addr)
        }
        50 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, addr) = parse_addr_v4(opt.v)?;
            DHCPOption::RequestedIPAddress(addr)
        }
        51 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, v) = be_u32(opt.v)?;
            DHCPOption::AddressLeaseTime(v)
        }
        52 => {
            nom_err_return!(i, opt.l != 1, ErrorKind::LengthValue);
            let (_, v) = be_u8(opt.v)?;
            DHCPOption::OptionOverload(v)
        }
        53 => {
            nom_err_return!(i, opt.l != 1, ErrorKind::LengthValue);
            let (_, v) = be_u8(opt.v)?;
            DHCPOption::MessageType(DHCPMessageType(v))
        }
        54 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, addr) = parse_addr_v4(opt.v)?;
            DHCPOption::ServerIdentifier(addr)
        }
        55 => DHCPOption::ParameterRequestList(DHCPParameterRequest(opt.v)),
        56 => DHCPOption::Message(opt.v),
        57 => {
            nom_err_return!(i, opt.l != 2, ErrorKind::LengthValue);
            let (_, v) = be_u16(opt.v)?;
            DHCPOption::MaximumSize(v)
        }
        58 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, v) = be_u32(opt.v)?;
            DHCPOption::Renewal(v)
        }
        59 => {
            nom_err_return!(i, opt.l != 4, ErrorKind::LengthValue);
            let (_, v) = be_u32(opt.v)?;
            DHCPOption::Rebinding(v)
        }
        60 => DHCPOption::ClassIdentifier(opt.v),
        61 => DHCPOption::ClientIdentifier(opt.v),
        255 => DHCPOption::End,
        _ => DHCPOption::Generic(opt),
    };
    Ok((i, opt))
}

fn parse_options(i: &[u8]) -> IResult<&[u8], Vec<DHCPOption>> {
    let mut acc = Vec::new();
    let mut i = i;
    loop {
        let (rem, opt) = parse_generic_option(i)?;
        let (rem, opt) = convert_generic_option(rem, opt)?;
        if let DHCPOption::End = opt {
            acc.push(opt);
            return Ok((rem, acc));
        }
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
