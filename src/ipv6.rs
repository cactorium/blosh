use std::net::Ipv6Addr;

use std::cmp::min;

use nom::{be_u8, be_u16, be_u32, rest, IResult};

use ::ipv4::Ipv4Protocol;

#[derive(Clone, Debug)]
pub struct Ipv6Packet<'a> {
    pub header: Ipv6Header,
    pub extensions: Vec<Ipv6Extension<'a>>,
    pub body: &'a [u8],
}

struct PacketBody<'a> {
    extensions: Vec<Ipv6Extension<'a>>,
    body: &'a [u8],
}

// TODO: handle Jumbo Packets correctly
named!(pub parse_ipv6_packet<Ipv6Packet>,
    do_parse!(
        header: parse_ipv6_header >>
        packet_body: flat_map!(
            take!(header.payload_length),
            do_parse!(
                extensions: call!(parse_extensions, header.next_header) >>
                payload: rest >>
                (PacketBody {
                    body: payload,
                    extensions: extensions,
                })
            )
        ) >>
        (Ipv6Packet {
            header: header,
            extensions: packet_body.extensions,
            body: packet_body.body
        })
    )
);


fn has_next_header(ht: Ipv6HeaderType) -> bool {
    match ht {
        Ipv6HeaderType::Ipv4(_) => false,
        Ipv6HeaderType::NoNext => false,
        _ => true,
    }
}

fn parse_extensions<'a>(mut bs: &'a [u8], mut header_type: Ipv6HeaderType) -> IResult<&'a [u8], Vec<Ipv6Extension<'a>>, u32> {
    let mut ret = Vec::new();
    while has_next_header(header_type) {
        let extensions_ret = parse_ipv6_extension(bs, header_type);
        match extensions_ret {
            IResult::Done(new_bs, extension) => {
                header_type = extension.next_header;
                ret.push(extension);
                bs = new_bs;
            },
            IResult::Incomplete(x) => return IResult::Incomplete(x),
            IResult::Error(x) => return IResult::Error(x),
        }
    }
    IResult::Done(bs, ret)
}


// TODO: wrap IP addresses in a struct to allow Deref to std::net::IpAddr 
#[derive(Clone, Copy, Debug)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: Ipv6HeaderType,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

struct Bitfields {
    traffic_class: u8,
    flow_label: u32,
}

pub fn slice2addr(ip: &[u8]) -> Ipv6Addr {
    let pair = |x, y| ((x as u16) << 8) | (y as u16);
    Ipv6Addr::new(
        pair(ip[0], ip[1]),
        pair(ip[2], ip[3]),
        pair(ip[4], ip[5]),
        pair(ip[6], ip[6]),
        pair(ip[8], ip[9]),
        pair(ip[10], ip[11]),
        pair(ip[12], ip[13]),
        pair(ip[14], ip[15]))
}

named!(pub parse_ipv6_header<Ipv6Header>,
    do_parse!(
        bitfields: bits!(
            do_parse!(
                tag_bits!(u8, 4, 6) >>
                traffic_class: take_bits!(u8, 8) >>
                flow_label: take_bits!(u32, 20) >>
                (Bitfields {
                    traffic_class: traffic_class,
                    flow_label: flow_label,
                })
            )
        ) >>
        payload_length: be_u16 >>
        next_header: be_u8 >>
        hop_limit: be_u8 >>
        src: take!(16) >>
        dst: take!(16) >>
        (Ipv6Header {
            traffic_class: bitfields.traffic_class,
            flow_label: bitfields.flow_label,
            payload_length: payload_length,
            next_header: Ipv6HeaderType::from_u8(next_header),
            hop_limit: hop_limit,
            src_ip: slice2addr(src),
            dst_ip: slice2addr(dst),
        })
    )
);


#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv6HeaderType {
    HopByHopOptions,
    Routing,
    Fragment,
    DestinationOptions,
    NoNext,
    Ipv4(::ipv4::Ipv4Protocol),
}

impl Ipv6HeaderType {
    pub fn from_u8(v: u8) -> Ipv6HeaderType {
        match v {
            0 => Ipv6HeaderType::HopByHopOptions,
            43 => Ipv6HeaderType::Routing,
            44 => Ipv6HeaderType::Fragment,
            60 => Ipv6HeaderType::DestinationOptions,
            59 => Ipv6HeaderType::NoNext,
            _ => Ipv6HeaderType::Ipv4(Ipv4Protocol::from_u8(v)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv6Extension<'a> {
    pub inner: Ipv6HeaderData<'a>,
    pub len: u8,
    pub next_header: Ipv6HeaderType,
}

named_args!(parse_hop(header_type:Ipv6HeaderType)<Ipv6Extension>,
    cond_reduce!(header_type == Ipv6HeaderType::HopByHopOptions,
        do_parse!(
            next_header: be_u8 >>
            len: be_u8 >>
            options: peek!(call!(parse_options, (8*len + 6) as usize)) >>
            take!((8*len + 6) as usize) >>
            (Ipv6Extension {
                inner: Ipv6HeaderData::HopByHopOptions(options),
                len: len,
                next_header: Ipv6HeaderType::from_u8(next_header),
            })
        )
    )
);

named_args!(parse_routing(header_type:Ipv6HeaderType)<Ipv6Extension>,
    cond_reduce!(header_type == Ipv6HeaderType::Routing,
        do_parse!(
            next_header: be_u8 >>
            len: be_u8 >>
            routing_type: be_u8 >>
            segments_left: be_u8 >>
            routing_data: take!((8*len + 4) as usize) >>
            (Ipv6Extension {
                inner: Ipv6HeaderData::Routing(routing_type, segments_left, routing_data),
                len: len,
                next_header: Ipv6HeaderType::from_u8(next_header),
            })
        )
    )
);

struct FragmentBitfield {
    frag_offset: u16,
    last_frag: bool,
}

named_args!(parse_fragment(header_type:Ipv6HeaderType)<Ipv6Extension>,
    cond_reduce!(header_type == Ipv6HeaderType::Fragment,
        do_parse!(
            next_header: be_u8 >>
            be_u8 >>
            bitfield: bits!(
                do_parse!(
                    fragment_offset: take_bits!(u16, 13) >>
                    take_bits!(u8, 2) >>
                    last_frag: take_bits!(u8, 1) >>
                    (FragmentBitfield {
                        frag_offset: fragment_offset,
                        last_frag: last_frag == 1,
                    })
                )
            ) >>
            id: be_u32 >>
            (Ipv6Extension {
                inner: Ipv6HeaderData::Fragment(bitfield.frag_offset, bitfield.last_frag, id),
                len: 2,
                next_header: Ipv6HeaderType::from_u8(next_header),
            })
        )
    )
);

named_args!(parse_destination(header_type:Ipv6HeaderType)<Ipv6Extension>,
    cond_reduce!(header_type == Ipv6HeaderType::DestinationOptions,
        do_parse!(
            next_header: be_u8 >>
            len: be_u8 >>
            options: peek!(call!(parse_options, (8*len + 6) as usize)) >>
            take!((8*len + 6) as usize) >>
            (Ipv6Extension {
                inner: Ipv6HeaderData::DestinationOptions(options),
                len: len,
                next_header: Ipv6HeaderType::from_u8(next_header),
            })
        )
    )
);

fn parse_ipv6_extension<'a>(bs: &'a [u8], header_type: Ipv6HeaderType) -> IResult<&'a [u8], Ipv6Extension<'a>, u32> {
    alt!(
        bs,
        call!(parse_hop, header_type) |
        call!(parse_routing, header_type) |
        call!(parse_fragment, header_type) |
        call!(parse_destination, header_type)
    )
}

// TODO: use type synonyms to give these nicer type names
#[derive(Clone, Debug)]
pub enum Ipv6HeaderData<'a> {
    HopByHopOptions(Vec<Ipv6Option<'a>>),
    Routing(u8, u8, &'a [u8]),
    Fragment(u16, bool, u32),
    DestinationOptions(Vec<Ipv6Option<'a>>),
    NoNext,
}

#[derive(Clone, Copy, Debug)]
pub enum Ipv6Option<'a> {
    Opt(u8, u8, &'a [u8]),
    Padding0,
    Padding1,
    Dummy,
}

fn eoo_check<'a>(bs: &'a [u8]) -> IResult<&'a [u8], Ipv6Option<'a>, u32> {
    cond_reduce!(bs, bs.len() == 0, value!(Ipv6Option::Dummy))
}

fn parse_options<'a>(bs: &'a [u8], len: usize) -> IResult<&'a [u8], Vec<Ipv6Option<'a>>, u32> {
    do_parse!(
        &bs[..min(bs.len(), len)],
        options: many_till!(
            alt!(
                call!(eoo_check) |
                map!(char!(0x00 as char), |_| Ipv6Option::Padding0) |
                do_parse!(
                    char!(0x01 as char) >>
                    len: be_u8 >>
                    take!((len-2) as usize) >>
                    (Ipv6Option::Padding1)) |
                do_parse!(
                    typ: be_u8 >>
                    len: be_u8 >>
                    data: take!((len-2) as usize) >>
                    (Ipv6Option::Opt(typ, len, data)))
            ),
            call!(eoo_check)
        ) >>
        ({
            let (mut opts, last) = options;
            opts.push(last);
            opts.into_iter()
                .filter(|x| match x {
                    &Ipv6Option::Dummy => false,
                    _ => true,
                })
                .collect()
        })
    )
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_ipv6() {
        let packet = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x24, 0x11, 0x40, 0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
            0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe, 0x05, 0x01, 0x48, 0x19, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x09, 0x5c, 0x00, 0x35, 0x00, 0x24, 0xf0, 0x09,
            0x00, 0x06, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x69, 0x74, 0x6f,
            0x6a, 0x75, 0x6e, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0xff, 0x00, 0x01,
        ];
        let (left, ip_packet) = parse_ipv6_packet(&packet).unwrap();
        assert_eq!(left.len(), 0);
        println!("{:?}", &ip_packet);
    }
}
