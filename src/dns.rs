use nom::{be_u8, be_u16, be_u32, rest};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    pub header: Header,
    pub questions: Vec<Query<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub authorities: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
}

named!(pub parse_dns_message<Message>,
    do_parse!(
        header: parse_dns_header >>
        questions: count!(query, header.qdcount as usize) >>
        answers: count!(resource_record, header.ancount as usize) >>
        authorities: count!(resource_record, header.nscount as usize) >>
        additional: count!(resource_record, header.arcount as usize) >>
        (Message {
            header: header,
            questions: questions,
            answers: answers,
            authorities: authorities,
            additional: additional,
        })
    )
);

pub struct RawHeader {
    id: u16,
    fields: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub id: u16,
    pub qr: QR,
    pub opcode: Opcode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub z: Z,
    pub rcode: Rcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn from(raw: RawHeader) -> Option<Header> {
        let qr = QR::from(raw.fields & 1);
        let opcode = Opcode::from((raw.fields >> 1) & 15);
        let aa = (raw.fields >> 5) & 1 == 1;
        let tc = (raw.fields >> 6) & 1 == 1;
        let rd = (raw.fields >> 7) & 1 == 1;
        let ra = (raw.fields >> 8) & 1 == 1;
        let z = Z::from((raw.fields >> 9) & 7);
        let rcode = Rcode::from((raw.fields >> 12) & 15);

        if !qr.is_some() {
            return None;
        }
        if !opcode.is_some() {
            return None;
        }
        if !z.is_some() {
            return None;
        }
        if !rcode.is_some() {
            return None;
        }

        Some(Header {
            id: raw.id,
            qr: qr.unwrap(),
            opcode: opcode.unwrap(),
            aa: aa,
            tc: tc,
            rd: rd,
            ra: ra,
            z: z.unwrap(),
            rcode: rcode.unwrap(),
            qdcount: raw.qdcount,
            ancount: raw.ancount,
            nscount: raw.nscount,
            arcount: raw.arcount,
        })
    }
}

named!(pub parse_dns_header< Header >,
    map_opt!(
        do_parse!(
            id: be_u16 >>
            fields: be_u16 >>
            qdcount: be_u16 >>
            ancount: be_u16 >>
            nscount: be_u16 >>
            arcount: be_u16 >>
            (RawHeader {
                id: id,
                fields: fields,
                qdcount: qdcount,
                ancount: ancount,
                nscount: nscount,
                arcount: arcount,
            })
        ),
        Header::from
    )
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QR {
    Query,
    Response,
}

impl QR {
    pub fn from(i: u16) -> Option<QR> {
        match i {
            0 => Some(QR::Query),
            1 => Some(QR::Response),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    Query,
    InverseQuery,
    Status,
    Reserved(u8),
}

impl Opcode {
    fn from(i: u16) -> Option<Opcode> {
        match i {
            0 => Some(Opcode::Query),
            1 => Some(Opcode::InverseQuery),
            2 => Some(Opcode::Status),
            _ => {
                if i < 16 {
                    Some(Opcode::Reserved(i as u8))
                } else {
                    None
                }
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Z;

impl Z {
    fn from(i: u16) -> Option<Z> {
        match i {
            0 => Some(Z),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Reserved(u8),
}

impl Rcode {
    fn from(i: u16) -> Option<Rcode> {
        match i {
            0 => Some(Rcode::NoError),
            1 => Some(Rcode::FormatError),
            2 => Some(Rcode::ServerFailure),
            3 => Some(Rcode::NameError),
            4 => Some(Rcode::NotImplemented),
            _ => {
                if i < 15 {
                    Some(Rcode::Reserved(i as u8))
                } else {
                    None
                }
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query<'a> {
    pub qname: Qname<'a>,
    pub qtype: Qtype,
    pub qclass: Qclass,
}
named!(query<Query>,
    do_parse!(
        qname: domain_name >>
        qtype: qtype >>
        qclass: qclass >>
        (Query {
            qname: qname,
            qtype: qtype,
            qclass: qclass,
        })
    )
);

pub type Qname<'a> = DomainName<'a>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainName<'a> {
    Labels(Vec<Label<'a>>),
    Pointer(u16),
    LabelWithPointer(Vec<Label<'a>>, u16),
}

named!(domain_name<DomainName>,
    alt!(labels | pointer | label_with_pointer)
);

named!(labels<DomainName>,
    map!(
        many_till!(call!(label), char!(0 as char) ),
        |(x, y)| DomainName::Labels(x)
    )
);

named!(pointer<DomainName>,
    map!(
        verify!(be_u16, |x| x > (0b11000000 << 8)),
        |x| DomainName::Pointer(x & !(0b11000000 << 8))
    )
);

named!(label_with_pointer<DomainName>,
    map!(
        many_till!(call!(label), call!(pointer)),
        |(x, y)| {
            if let DomainName::Pointer(y) = y {
                return DomainName::LabelWithPointer(x, y);
            }
            unreachable!("label_with_pointer: pointer returned non-pointer value");
        }
    )
);

pub type Label<'a> = &'a [u8];
named!(label,
    do_parse!(
        len: verify!(be_u8, |x| x < 0b11000000) >>
        label: take!(len) >>
        (label)
    )
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Qtype {
    Type(Type),
    Axfr,
    MailB,
    MailA,
    Wildcard,
}

impl Qtype {
    pub fn from(v: u16) -> Option<Qtype> {
        let typ = Type::from(v);
        if let Some(typ) = typ {
            return Some(Qtype::Type(typ));
        }

        match v {
            252 => Some(Qtype::Axfr),
            253 => Some(Qtype::MailB),
            254 => Some(Qtype::MailA),
            255 => Some(Qtype::Wildcard),
            _ => None,
        }
    }
}
named!(qtype<Qtype>,
    map_opt!(
        be_u16,
        Qtype::from
    )
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Qclass {
    Class(Class),
    Wildcard,
}

impl Qclass {
    pub fn from(v: u16) -> Option<Qclass> {
        let class = Class::from(v);
        if let Some(class) = class {
            return Some(Qclass::Class(class));
        }

        match v {
            255 => Some(Qclass::Wildcard),
            _ => None,
        }

    }
}

named!(qclass<Qclass>,
    map_opt!(
        be_u16,
        Qclass::from
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRecord<'a> {
    pub name: DomainName<'a>,
    pub typ: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata: Rdata<'a>,
}

named!(resource_record<ResourceRecord>,
    do_parse!(
        name: domain_name >>
        typ: parse_type >>
        class: parse_class >>
        ttl: be_u32 >>
        rdlen: be_u16 >>
        rdata: map_opt!(take!(rdlen), |data| Rdata::from(typ, data)) >>
        (ResourceRecord {
            name: name,
            typ: typ,
            class: class,
            ttl: ttl,
            rdata: rdata,
        })
    )
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Type {
    A,
    NS,
    MD,
    MF,
    Cname,
    SOA,
    MB,
    MG,
    MR,
    Null,
    WKS,
    Ptr,
    Hinfo,
    Minfo,
    MX,
    Txt,
}

impl Type {
    pub fn from(v: u16) -> Option<Type> {
        match v {
            1 => Some(Type::A),
            2 => Some(Type::NS),
            3 => Some(Type::MD),
            4 => Some(Type::MF),
            5 => Some(Type::Cname),
            6 => Some(Type::SOA),
            7 => Some(Type::MB),
            8 => Some(Type::MG),
            9 => Some(Type::MR),
            10 => Some(Type::Null),
            11 => Some(Type::WKS),
            12 => Some(Type::Ptr),
            13 => Some(Type::Hinfo),
            14 => Some(Type::Minfo),
            15 => Some(Type::MX),
            16 => Some(Type::Txt),
            _ => None,
        }
    }
}

named!(parse_type<Type>,
    map_opt!(
        be_u16,
        Type::from
    )
);


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    IN,
    CS,
    CH,
    HS,
}

impl Class {
    pub fn from(v: u16) -> Option<Class> {
        match v {
            1 => Some(Class::IN),
            2 => Some(Class::CS),
            3 => Some(Class::CH),
            4 => Some(Class::HS),
            _ => None,
        }
    }
}

named!(parse_class<Class>,
    map_opt!(
        be_u16,
        Class::from
    )
);


#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rdata<'a> {
    Cname(DomainName<'a>),
    Hinfo(Hinfo<'a>),
    MB(DomainName<'a>),
    MD(DomainName<'a>),
    MF(DomainName<'a>),
    MG(DomainName<'a>),
    Minfo(Minfo<'a>),
    MR(DomainName<'a>),
    MX(MX<'a>),
    Null(&'a [u8]),
    NS(DomainName<'a>),
    Ptr(DomainName<'a>),
    Soa(Soa<'a>),
    Txt(Vec<CharacterString<'a>>),
    A([u8; 4]),
    Wks(Wks<'a>),
    Unknown(&'a [u8]),
}

impl <'a> Rdata<'a> {
    pub fn from(typ: Type, raw: &'a [u8]) -> Option<Rdata<'a>> {
        match typ {
            Type::A => {
                if raw.len() >= 4 {
                    Some(Rdata::A([raw[3], raw[2], raw[1], raw[0]]))
                } else {
                    None
                }
            },
            Type::NS => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::NS)
            },
            Type::MD => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MD)
            },
            Type::MF => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MF)
            },
            Type::Cname => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Cname)
            },
            Type::SOA => {
                parse_soa(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Soa)
            },
            Type::MB => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MB)
            },
            Type::MG => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MG)
            },
            Type::MR => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MR)
            },
            Type::Null => {
                Some(Rdata::Null(raw))
            },
            Type::WKS => {
                parse_wks(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Wks)
            },
            Type::Ptr => {
                domain_name(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Ptr)
            },
            Type::Hinfo => {
                hinfo(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Hinfo)
            },
            Type::Minfo => {
                minfo(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Minfo)
            },
            Type::MX => {
                parse_mx(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::MX)
            },
            Type::Txt => {
                parse_txt(raw)
                    .to_result()
                    .ok()
                    .map(Rdata::Txt)
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hinfo<'a> {
    pub cpu: CharacterString<'a>,
    pub os: CharacterString<'a>,
}
named!(hinfo<Hinfo>,
    do_parse!(
        cpu: parse_char_string >>
        os: parse_char_string >>
        (Hinfo {
            cpu: cpu,
            os: os,
        })
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Minfo<'a> {
    pub rmailbox: DomainName<'a>,
    pub emailbox: DomainName<'a>,
}
named!(minfo<Minfo>,
    do_parse!(
        rbox: domain_name >>
        ebox: domain_name >>
        (Minfo {
            rmailbox: rbox,
            emailbox: ebox,
        })
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MX<'a> {
    pub preference: u16,
    pub exchange: DomainName<'a>,
}
named!(parse_mx<MX>,
    do_parse!(
        preference: be_u16 >>
        exchange: domain_name >>
        (MX {
            preference: preference,
            exchange: exchange,
        })
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Soa<'a> {
    pub mname: DomainName<'a>,
    pub rname: DomainName<'a>,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
}
named!(parse_soa<Soa>,
    do_parse!(
        mname: domain_name >>
        rname: domain_name >>
        serial: be_u32 >>
        refresh: be_u32 >>
        retry: be_u32 >>
        expire: be_u32 >>
        minimum: be_u32 >>
        (Soa {
            mname: mname,
            rname: rname,
            serial: serial,
            refresh: refresh,
            retry: retry,
            expire: expire,
            minimum: minimum,
        })
    )
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CharacterString<'a>(&'a [u8]);
named!(parse_char_string<CharacterString>,
    do_parse!(
        len: be_u8 >>
        string: take!(len as usize) >>
        (CharacterString(string))
    )
);

named!(parse_txt< Vec<CharacterString> >,
    many1!(parse_char_string)
);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Wks<'a> {
    pub address: [u8; 4],
    pub protocol: u8,
    pub bitmap: &'a [u8],
}
named!(parse_wks<Wks>,
    do_parse!(
        address: take!(4) >>
        protocol: be_u8 >>
        bitmap: rest >>
        (Wks {
            address: [address[3], address[2], address[1], address[0]],
            protocol: protocol,
            bitmap: bitmap
        })
    )
);

#[cfg(test)]
mod tests {
    use nom::IResult;

    use super::*;
    #[test]
    fn test_query() {
        let query = [
            0x24, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01];
        assert_eq!(
            parse_dns_message(&query),
            IResult::Done(&b""[..],
                Message {
                    header: Header {
                        id: 9242,
                        qr: QR::Query,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: false,
                        ra: true,
                        z: Z,
                        rcode: Rcode::NoError,
                        qdcount: 1,
                        ancount: 0,
                        nscount: 0,
                        arcount: 0
                    },
                    questions: vec![
                        Query {
                            qname: DomainName::Labels(vec![
                                       &[119, 119, 119],
                                       &[103, 111, 111, 103, 108, 101],
                                       &[99, 111, 109]]),
                            qtype: Qtype::Type(Type::A),
                            qclass: Qclass::Class(Class::IN)
                        }
                    ],
                    answers: vec![],
                    authorities: vec![],
                    additional: vec![]
                })
        );
    }
}
