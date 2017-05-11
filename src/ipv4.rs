use nom::{be_u8, be_u16, IResult};

#[derive(Clone, Debug)]
pub struct Packet<'a> {
    pub header: Header<'a>,
    pub payload: &'a [u8],
}

pub fn parse_ipv4_packet<'a>(bs: &'a [u8]) -> IResult<&'a [u8], Packet<'a>, u32> {
    match parse_ipv4_header(bs) {
        IResult::Done(_, header) => {
            IResult::Done(&bs[header.total_len as usize..], Packet {
                payload: &bs[4*header.len as usize..],
                header: header,
            })
        },
        IResult::Incomplete(x) => IResult::Incomplete(x),
        IResult::Error(x) => IResult::Error(x),
    }
}

#[derive(Clone, Debug)]
pub struct Header<'a> {
    pub len: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: Flags,
    pub fragment_off: u16,
    pub ttl: u8,
    pub proto: u8,
    pub checksum: u16,
    // NOTE: network order; MSB first
    pub source_ip: &'a[u8],
    // NOTE: network order; MSB first
    pub dst_ip: &'a[u8],
    pub options: Vec<PacketOption<'a>>,
}

#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub df: bool,
    pub mf: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum PacketOption<'a> {
    EndOfOption,
    NoOperation,
    Other(u8, u8, &'a [u8])
}

named!(parse_options<Vec<PacketOption> >,
   do_parse!(
        options: many_till!(
            alt!(
                do_parse!(
                    _a: char!(0x01 as char) >>
                    (PacketOption::NoOperation)
                ) |
                do_parse!(
                    class: be_u8 >>
                    length: be_u8 >>
                    data: take!(length - 2) >>
                    (PacketOption::Other(class, length, data))
                )
            ),
            do_parse!(
                _a: char!(0x00 as char) >>
                (PacketOption::EndOfOption)
            )
        ) >> 
        ({
            let (mut options, last) = options;
            options.push(last);
            options
        })
    )
);


pub fn parse_ipv4_header<'a>(bs: &'a [u8]) -> IResult<&'a [u8], Header<'a>, u32> {
    do_parse!(
        bs,
        first_bits: bits!(
            do_parse!(
                _a: tag_bits!(u8, 4, 0b0100) >>
                len: take_bits!(u8, 4) >>
                dscp: take_bits!(u8, 6) >>
                ecn: take_bits!(u8, 2) >>
                ((len, dscp, ecn))
            )
        ) >>
        total_len: be_u16 >>
        id: be_u16 >>
        second_bits: bits!(
            do_parse!(
                _reserved: tag_bits!(u8, 1, 0) >>
                df: take_bits!(u8, 1) >>
                mf: take_bits!(u8, 1) >>
                fragment_off: take_bits!(u16, 13) >>
                ((df, mf, fragment_off))
            )
        ) >>
        ttl: be_u8 >>
        proto: be_u8 >>
        checksum: be_u16 >>
        source: take!(4) >>
        dst: take!(4) >>
        options: cond!(first_bits.0 > 5,
            parse_options
        ) >>
        ({
            let unwrapped_options = match options {
                Some(options) => {
                    options
                },
                None => vec![],
            };
            Header {
                len: first_bits.0,
                dscp: first_bits.1,
                ecn: first_bits.2,
                total_len: total_len,
                id: id,
                flags: Flags {
                    df: second_bits.0 == 1,
                    mf: second_bits.1 == 1,
                },
                fragment_off: second_bits.2,
                ttl: ttl,
                proto: proto, // TODO: wrap in enum
                checksum: checksum,
                source_ip: source,
                dst_ip: dst,
                options: unwrapped_options,
            }
        })
    )
}
