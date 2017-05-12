use nom::{be_u8, be_u16, IResult};

#[derive(Clone, Debug)]
pub struct Ipv4Packet<'a> {
    pub header: Header<'a>,
    pub body: &'a [u8],
}

pub fn parse_ipv4_packet<'a>(bs: &'a [u8]) -> IResult<&'a [u8], Ipv4Packet<'a>, u32> {
    use std::cmp::min;
    match parse_ipv4_header(bs) {
        IResult::Done(_, header) => {
            IResult::Done(&b""[..], Ipv4Packet {
                body: &bs[min(4*header.len as usize, bs.len())..],
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
    pub proto: Ipv4Protocol,
    pub checksum: u16,
    // NOTE: network order; MSB first
    pub source_ip: &'a[u8],
    // NOTE: network order; MSB first
    pub dst_ip: &'a[u8],
    pub options: Vec<Ipv4Option<'a>>,
}

#[derive(Clone, Copy, Debug)]
pub struct Flags {
    pub df: bool,
    pub mf: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum Ipv4Option<'a> {
    EndOfOption,
    NoOperation,
    Other(u8, u8, &'a [u8]),
    Dummy
}

fn test_eof<'a>(bs: &'a [u8]) -> IResult<&'a [u8], Ipv4Option<'a>, u32> {
    cond_reduce!(bs, bs.len() == 0, value!(Ipv4Option::Dummy))
}


named!(parse_options<Vec<Ipv4Option> >,
   do_parse!(
        options: many_till!(
            alt!(
                call!(test_eof) |
                do_parse!(
                    _a: char!(0x01 as char) >>
                    (Ipv4Option::NoOperation)
                ) |
                do_parse!(
                    class: be_u8 >>
                    length: be_u8 >>
                    data: take!(length - 2) >>
                    (Ipv4Option::Other(class, length, data))
                )
            ),
            alt!(
                call!(test_eof) |
                do_parse!(
                    _a: char!(0x00 as char) >>
                    (Ipv4Option::EndOfOption)
                )
            )
        ) >> 
        ({
            let (mut options, last) = options;
            options.push(last);
            options
                .into_iter()
                .filter(|o| match o {
                    &Ipv4Option::Dummy => false,
                    _ => true,
                })
                .collect()
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
                proto: Ipv4Protocol::from_u8(proto),
                checksum: checksum,
                source_ip: source,
                dst_ip: dst,
                options: unwrapped_options,
            }
        })
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipv4Protocol {
    Icmp,
    Igmp,
    Ggp,
    Ip,
    St,
    Tcp,
    Ucl,
    Egp,
    Igp,
    BbnRccMon,
    NvpII,
    Pup,
    Argus,
    Emcon,
    Xnet,
    Chaos,
    Udp,
    Mux,
    DcnMeas,
    Hmp,
    Prm,
    XndIdp,
    Trunk1,
    Trunk2,
    Leaf1,
    Leaf2,
    Rdp,
    Irtp,
    IsoTp4,
    Netblt,
    MfeNsp,
    MeritInp,
    Sep,
    ThreePC,
    Idpr,
    Xtp,
    Ddp,
    IdprCmtp,
    TpPlusPlus,
    Il,
    Sip,
    Sdrp,
    SipSr,
    SipFrag,
    Idrp,
    Rsvp,
    Gre,
    Mhrp,
    Bna,
    SippEsp,
    SippAh,
    INlsp,
    Swipe,
    Nhrp,
    Cftp,
    SatExpak,
    Kryptolan,
    Rvd,
    Ippc,
    SatMon,
    Visa,
    Ipcv,
    Cpnx,
    Cphb,
    Wsn,
    Pvp,
    BrSatMon,
    SunNd,
    WbMon,
    WbExpak,
    IsoIp,
    Vmtp,
    SecureVmtp,
    Vines,
    Ttp,
    NsfnetIgp,
    Dgp,
    Tcf,
    Igrp,
    Ospfigp,
    SpriteRpc,
    Larp,
    Mtp,
    Ax25,
    Ipip,
    Micp,
    SccSp,
    Etherip,
    Encap,
    Gmtp,
    Other(u8),
}

impl Ipv4Protocol {
    pub fn from_u8(v: u8) -> Ipv4Protocol {
        use self::Ipv4Protocol::*;
        match v {
            1 => Icmp,
            2 => Igmp,
            3 => Ggp,
            4 => Ip,
            5 => St,
            6 => Tcp,
            7 => Ucl,
            8 => Egp,
            9 => Igp,
            10 => BbnRccMon,
            11 => NvpII,
            12 => Pup,
            13 => Argus,
            14 => Emcon,
            15 => Xnet,
            16 => Chaos,
            17 => Udp,
            18 => Mux,
            19 => DcnMeas,
            20 => Hmp,
            21 => Prm,
            22 => XndIdp,
            23 => Trunk1,
            24 => Trunk2,
            25 => Leaf1,
            26 => Leaf2,
            27 => Rdp,
            28 => Irtp,
            29 => IsoTp4,
            30 => Netblt,
            31 => MfeNsp,
            32 => MeritInp,
            33 => Sep,
            34 => ThreePC,
            35 => Idpr,
            36 => Xtp,
            37 => Ddp,
            38 => IdprCmtp,
            39 => TpPlusPlus,
            40 => Il,
            41 => Sip,
            42 => Sdrp,
            43 => SipSr,
            44 => SipFrag,
            45 => Idrp,
            46 => Rsvp,
            47 => Gre,
            48 => Mhrp,
            49 => Bna,
            50 => SippEsp,
            51 => SippAh,
            52 => INlsp,
            53 => Swipe,
            54 => Nhrp,
            62 => Cftp,
            64 => SatExpak,
            65 => Kryptolan,
            66 => Rvd,
            67 => Ippc,
            69 => SatMon,
            70 => Visa,
            71 => Ipcv,
            72 => Cpnx,
            73 => Cphb,
            74 => Wsn,
            75 => Pvp,
            76 => BrSatMon,
            77 => SunNd,
            78 => WbMon,
            79 => WbExpak,
            80 => IsoIp,
            81 => Vmtp,
            82 => SecureVmtp,
            83 => Vines,
            84 => Ttp,
            85 => NsfnetIgp,
            86 => Dgp,
            87 => Tcf,
            88 => Igrp,
            89 => Ospfigp,
            90 => SpriteRpc,
            91 => Larp,
            92 => Mtp,
            93 => Ax25,
            94 => Ipip,
            95 => Micp,
            96 => SccSp,
            97 => Etherip,
            98 => Encap,
            100 => Gmtp,
            x => Ipv4Protocol::Other(x),
        }
    }
}
