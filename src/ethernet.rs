use nom::{rest, IResult};

#[derive(Clone, Debug)]
pub struct EthernetIIPacket<'a> {
    pub dest_mac: &'a [u8],
    pub source_mac: &'a [u8],
    pub body: &'a [u8],
}

// NOTE: will break if the bytestring isn't long enough
// TODO: fix that
pub fn parse_eth2_packet<'a>(bs: &'a [u8]) -> IResult<&'a [u8], EthernetIIPacket<'a>, u32> {
    do_parse!(
        bs,
        dest: take!(6) >>
        src: take!(6) >>
        _ethertyp: tag!(b"\x08\x00") >>
        rest: rest >>
        ({
            EthernetIIPacket {
                dest_mac: dest,
                source_mac: src,
                body: rest,
            }
        })
    )
}
