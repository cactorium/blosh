use nom::{be_u8, be_u16, be_u32, IResult};

// https://tools.ietf.org/html/rfc793
#[derive(Clone, Debug)]
pub struct TcpPacket<'a> {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: TcpFlags,
    pub window_sz: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub options: Vec<TcpOption<'a>>,
    pub body: &'a [u8],
}

struct Bits {
    pub offset: u8,
    pub ns: u8,
    pub cwr: u8,
    pub ece: u8,
    pub urg: u8,
    pub ack: u8,
    pub psh: u8,
    pub rst: u8,
    pub syn: u8,
    pub fin: u8,
}

pub fn parse_tcp_packet<'a>(bs: &'a [u8]) -> IResult<&'a [u8], TcpPacket<'a>, u32> {
    do_parse!(
        bs,
        src: be_u16 >>
        dst: be_u16 >>
        seq: be_u32 >>
        ack: be_u32 >>
        bits: bits!(
            do_parse!(
                offset: take_bits!(u8, 4) >>
                _reserved: tag_bits!(u8, 3, 0) >>
                ns: take_bits!(u8, 1) >>
                cwr: take_bits!(u8, 1) >>
                ece: take_bits!(u8, 1) >>
                urg: take_bits!(u8, 1) >>
                ack: take_bits!(u8, 1) >>
                psh: take_bits!(u8, 1) >>
                rst: take_bits!(u8, 1) >>
                syn: take_bits!(u8, 1) >>
                fin: take_bits!(u8, 1) >>
                (Bits {
                    offset: offset,
                    ns: ns,
                    cwr: cwr,
                    ece: ece,
                    urg: urg,
                    ack: ack,
                    psh: psh,
                    rst: rst,
                    syn: syn,
                    fin: fin,
                })
            )
        ) >>
        sz: be_u16 >>
        sum: be_u16 >>
        urgent: be_u16 >>
        options: cond!(bits.offset > 5, apply!(parse_options, (4*bits.offset-20) as usize)) >>
        ({
            let mut header = TcpPacket {
                src: src,
                dst: dst,
                seq: seq,
                ack: ack,
                body: &bs[4*bits.offset as usize..],
                flags: TcpFlags::from_bits(bits),
                window_sz: sz,
                checksum: sum,
                urgent: urgent,
                options: vec![],
            };

            match options {
                Some(options) => header.options = options,
                None => {},
            }

            header
        })
    )
}

#[derive(Clone, Copy, Debug)]
pub struct TcpFlags {
    pub offset: u8,
    pub ns: bool,
    pub cwr: bool,
    pub ece: bool,
    pub urg: bool,
    pub ack: bool,
    pub psh: bool,
    pub rst: bool,
    pub syn: bool,
    pub fin: bool,
}

impl TcpFlags {
    fn from_bits(bits: Bits) -> TcpFlags {
        TcpFlags {
            offset: bits.offset,
            fin: bits.fin == 1,
            syn: bits.syn == 1,
            rst: bits.rst == 1,
            psh: bits.psh == 1,
            ack: bits.ack == 1,
            urg: bits.urg == 1,
            ece: bits.ece == 1,
            cwr: bits.cwr == 1,
            ns: bits.ns == 1,
        }
    }
}


fn known_options<'a>(bs: &'a [u8]) -> IResult<&'a [u8], TcpOption<'a>, u32> {
   alt!(
        bs,
        call!(eof_check) |
        do_parse!(
            _a: char!(0x01 as char) >>
            (TcpOption::NoOperation)
        ) |
        do_parse!(
            _a: char!(0x02 as char) >>
            _a: char!(0x04 as char) >>
            seg_size: be_u16 >>
            (TcpOption::MaximumSegmentSize(seg_size))
        ) |
        do_parse!(
            _a: char!(0x03 as char) >>
            _a: char!(0x03 as char) >>
            shift: be_u8 >>
            (TcpOption::WindowScale(shift))
        ) |
        do_parse!(
            _a: char!(0x08 as char) >>
            _a: char!(0x0a as char) >>
            ts_val: be_u32 >>
            ts_ecr: be_u32 >>
            (TcpOption::Timestamps(ts_val, ts_ecr))
        ) |
        do_parse!(
            kind: be_u8 >>
            len: be_u8 >>
            data: take!(len - 2) >>
            (TcpOption::Other(kind, len, data))
        )
    )
}

// FIXME: make this nicer
fn eof_check<'a>(bs: &'a [u8]) -> IResult<&'a [u8], TcpOption<'a>, u32> {
    map!(
        bs,
        eof!(),
        |_| TcpOption::DummyOption)
}

fn end_of_options<'a>(bs: &'a [u8]) -> IResult<&'a [u8], TcpOption<'a>, u32> {
    alt!(
        bs,
        do_parse!(
            _a: char!(0x00 as char) >>
            (TcpOption::EndOfOptionList)
        ) |
        call!(eof_check)
    )
}

fn parse_options<'a>(bs: &'a [u8], len: usize) -> IResult<&'a [u8], Vec<TcpOption<'a>>, u32> {
    do_parse!(
        &bs[0..len],
        options: many_till!(
            call!(known_options),
            call!(end_of_options)
        ) >>
        ({
            let (mut options, end) = options;
            options.push(end);

            options
                .into_iter()
                .filter(|o| match o {
                    &TcpOption::DummyOption => false,
                    _ => true,
                }).collect()
        })
    )
}

#[derive(Clone, Copy, Debug)]
pub enum TcpOption<'a> {
    DummyOption,
    EndOfOptionList,
    NoOperation,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    Timestamps(u32, u32),
    MD5(&'a [u8]),
    Other(u8, u8, &'a [u8]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult;

    #[test]
    fn test_ip_flags() {
        // TODO
        unimplemented!()
    }
}
