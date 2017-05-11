use nom::{rest, be_u16};

pub struct UdpHeader {
    pub src: u16,
    pub dst: u16,
    pub len: u16,
    pub checksum: u16,
}

named!(pub parse_udp_header<UdpHeader>,
    do_parse!(
        src: be_u16 >>
        dst: be_u16 >>
        len: be_u16 >>
        checksum: be_u16 >>
        (UdpHeader {
            src: src,
            dst: dst,
            len: len,
            checksum: checksum,
        })
    )
);

pub struct UdpPacket<'a> {
    pub header: UdpHeader,
    pub body: &'a [u8],
}

named!(pub parse_udp_packet<UdpPacket>,
    do_parse!(
        header: parse_udp_header >>
        body: rest >>
        (UdpPacket {
            header: header,
            body: body,
        })
    )
);
