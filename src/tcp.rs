use nom::{be_u8, be_u16, be_u32, IResult};

pub struct RawTcpHeader {
    pub src: u16,
    pub dst: u16,
    pub seq: u32,
    pub ack: u32,
    pub bits: u16,
    pub window_sz: u16,
    pub checksum: u16,
}

named!(parse_raw_header<RawTcpHeader>,
    do_parse!(
        src: be_u16 >>
        dst: be_u16 >>
        seq: be_u32 >>
        ack: be_u32 >>
        bits: be_u16 >>
        sz: be_u16 >>
        sum: be_u16 >>
        urgent: be_u16 >>
        (RawTcpHeader {
            src: src,
            dst: dst,
            seq: seq,
            ack: ack,
            bits: bits,
            window_sz: sz,
            checksum: sum,
        })
    )
);

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
    fn from_half_word(w: u16) -> TcpFlags {
        TcpFlags {
            offset: ((w >> 12) & 15) as u8,
            fin: ((w >> 0) & 1) == 1,
            syn: ((w >> 1) & 1) == 1,
            rst: ((w >> 2) & 1) == 1,
            psh: ((w >> 3) & 1) == 1,
            ack: ((w >> 4) & 1) == 1,
            urg: ((w >> 5) & 1) == 1,
            ece: ((w >> 6) & 1) == 1,
            cwr: ((w >> 7) & 1) == 1,
            ns: ((w >> 8) & 1) == 1,
        }
    }
}


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
    pub options: Vec<TcpOption<'a>>,
    pub body: &'a [u8],
}

pub fn parse_tcp_packet<'a>(bytestr: &'a [u8]) -> IResult<&'a [u8], TcpPacket<'a>, u32> {
    match parse_raw_header(bytestr) {
        IResult::Done(left, raw_header) => {
            let flags =TcpFlags::from_half_word(raw_header.bits);
            let mut packet = TcpPacket {
                src: raw_header.src,
                dst: raw_header.dst,
                seq: raw_header.seq,
                ack: raw_header.ack,
                flags: flags,
                window_sz: raw_header.window_sz,
                checksum: raw_header.checksum,
                options: vec![],
                body: &bytestr[4*flags.offset as usize..],
            };

            if flags.offset > 5 {
                match parse_options(left) {
                    IResult::Done(_, options) => {
                        packet.options = options;
                    },
                    IResult::Incomplete(a) => return IResult::Incomplete(a),
                    IResult::Error(e) => return IResult::Error(e),
                }
            }

            IResult::Done(left, packet)
        },
        IResult::Incomplete(a) => IResult::Incomplete(a),
        IResult::Error(e) => IResult::Error(e),
    }
}

named!(parse_options<Vec<TcpOption> >,
    do_parse!(
        options: many_till!(
            alt!(
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
            ),
            do_parse!(
                _a: char!(0x00 as char) >>
                (TcpOption::EndOfOptionList)
            )
        ) >>
        ({
            let (mut options, end) = options;
            options.push(end);
            options
        })
    )
);

#[derive(Clone, Copy, Debug)]
pub enum TcpOption<'a> {
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
