use nom::{be_u8, be_u16, be_u32, rest, IResult};

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

/// Convert domain name pointers to byte slices
pub fn parse_dns_message_full<'a>(bytestr: &'a [u8]) -> IResult<&'a [u8], Message<'a>, u32> {
    use std::collections::HashMap;

    fn deref_helper<'a>(domain: &DomainName<'a>, dict: &mut HashMap<u16, DomainName<'a>>, bytestr: &'a [u8]) -> Option<DomainName<'a>> {
        match domain {
            &DomainName::Pointer(ref off) => {
                if dict.contains_key(off) {
                    Some(dict[off].clone())
                } else {
                    let new_domain_ref = domain_name(&bytestr[*off as usize..]);
                    match new_domain_ref {
                        IResult::Done(_, domain) => {
                            dict.insert(*off, domain.clone());
                            Some(domain)
                        },
                        _ => None,
                    }
                }
            },
            &DomainName::LabelWithPointer(ref list, ref off) => {
                let mut list = list.clone();
                let to_add = if dict.contains_key(off) {
                    dict[off].clone()
                } else {
                    let new_domain_ref = domain_name(&bytestr[*off as usize..]);
                    match new_domain_ref {
                        IResult::Done(_, domain_name) => {
                            dict.insert(*off, domain_name.clone());
                            domain_name
                        },
                        _  => {
                            return None;
                        },
                    }
                };
                if let DomainName::Labels(ref to_add) = to_add {
                    list.extend(to_add);
                    Some(DomainName::Labels(list))
                } else {
                    None
                }
            },
            x => Some(x.clone()),
        }
    }

    fn domain_deref<'a>(domain: &DomainName<'a>, dict: &mut HashMap<u16, DomainName<'a>>, bytestr: &'a [u8]) -> Option<DomainName<'a>> {
        let mut out = deref_helper(domain, dict, bytestr);
        fn recurse<'a>(d: &Option<DomainName<'a>>) -> bool {
            match d {
                &Some(DomainName::Labels(_)) => false,
                &Some(_) => true,
                &None => false,
            }
        }
        let mut should_recurse = recurse(&out);
        while should_recurse {
            let new_out = match out {
                Some(domain) => deref_helper(&domain, dict, bytestr),
                _ => None,
            };
            out = new_out;
            should_recurse = recurse(&out);
        }
        out
    }

    fn fix_record<'a>(record: &mut ResourceRecord<'a>, dict: &mut HashMap<u16, DomainName<'a>>,
                      bytestr: &'a [u8]) {
        match domain_deref(&record.name, dict, bytestr) {
            Some(domain) => record.name = domain,
            _ => {},
        }

        // TODO: check the rdata field to see if it's a domain name
        match &mut record.rdata {
            &mut Rdata::Cname(ref mut domain) | &mut Rdata::MB(ref mut domain) |
                &mut Rdata::MD(ref mut domain) | &mut Rdata::MF(ref mut domain) |
                &mut Rdata::MG(ref mut domain) | &mut Rdata::MR(ref mut domain) |
                &mut Rdata::NS(ref mut domain) | &mut Rdata::Ptr(ref mut domain) => {
                    match domain_deref(&domain, dict, bytestr) {
                        Some(new_domain) => *domain = new_domain,
                        _ => {},
                    }
            },
            &mut Rdata::Minfo(ref mut minfo) => {
                match domain_deref(&minfo.rmailbox, dict, bytestr) {
                    Some(new_domain) => minfo.rmailbox = new_domain,
                    _ => {},
                }
                match domain_deref(&minfo.emailbox, dict, bytestr) {
                    Some(new_domain) => minfo.emailbox = new_domain,
                    _ => {},
                }
            },
            &mut Rdata::MX(ref mut mx) => {
                match domain_deref(&mx.exchange, dict, bytestr) {
                    Some(new_domain) => mx.exchange = new_domain,
                    _ => {},
                }
            },
            &mut Rdata::Soa(ref mut soa) => {
                match domain_deref(&soa.mname, dict, bytestr) {
                    Some(new_domain) => soa.mname= new_domain,
                    _ => {},
                }
                match domain_deref(&soa.rname, dict, bytestr) {
                    Some(new_domain) => soa.rname = new_domain,
                    _ => {},
                }
            },
            &mut Rdata::Hinfo(_) | &mut Rdata::Null(_) | &mut Rdata::Txt(_) |
                &mut Rdata::A(_) | &mut Rdata::Wks(_) | &mut Rdata::AAAA(_) |
                &mut Rdata::Unknown(_) => {},
        }
    }

    parse_dns_message(bytestr)
        .map(|mut msg| {
            let mut parsed_pointers: HashMap<u16, DomainName<'a>> = HashMap::new();
            for query in msg.questions.iter_mut() {
                let change_name = match &query.qname {
                    &DomainName::Pointer(_) | &DomainName::LabelWithPointer(_, _) => true,
                    _ => false,
                };
                if change_name {
                    match domain_deref(&query.qname, &mut parsed_pointers, bytestr) {
                        Some(domain) => query.qname = domain,
                        _ => {},
                    }
                }
            }
            for answer in msg.answers.iter_mut() {
                fix_record(answer, &mut parsed_pointers, bytestr);
            }
            for authority in msg.authorities.iter_mut() {
                fix_record(authority, &mut parsed_pointers, bytestr);
            }
            for record in msg.additional.iter_mut() {
                fix_record(record, &mut parsed_pointers, bytestr);
            }
            msg
        })
}

pub struct RawHeader {
    id: u16,
    fields: Bits,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

struct Bits {
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    rcode: u8,
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
    pub rcode: Rcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl Header {
    pub fn from(raw: RawHeader) -> Option<Header> {
        let qr = QR::from(raw.fields.qr);
        let opcode = Opcode::from(raw.fields.opcode);
        let aa = raw.fields.aa & 1 == 1;
        let tc = raw.fields.tc & 1 == 1;
        let rd = raw.fields.rd & 1 == 1;
        let ra = raw.fields.ra & 1 == 1;
        let rcode = Rcode::from(raw.fields.rcode);

        if !qr.is_some() {
            return None;
        }
        if !opcode.is_some() {
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
            fields: bits!(
                do_parse!(
                    qr: take_bits!(u8, 1) >>
                    opcode: take_bits!(u8, 4) >>
                    aa: take_bits!(u8, 1) >>
                    tc: take_bits!(u8, 1) >>
                    rd: take_bits!(u8, 1) >>
                    ra: take_bits!(u8, 1) >>
                    _z: tag_bits!(u8, 3, 0) >>
                    rcode: take_bits!(u8, 4) >>
                    (Bits {
                        qr: qr,
                        opcode: opcode,
                        aa: aa,
                        tc: tc,
                        rd: rd,
                        ra: ra,
                        rcode: rcode,
                    })
                )
            ) >>
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
    pub fn from(i: u8) -> Option<QR> {
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
    fn from(i: u8) -> Option<Opcode> {
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
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Reserved(u8),
}

impl Rcode {
    fn from(i: u8) -> Option<Rcode> {
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
    AAAA,
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
            28 => Some(Type::AAAA),
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
    A(&'a [u8]),
    Wks(Wks<'a>),
    AAAA(&'a [u8]),
    Unknown(&'a [u8]),
}

impl <'a> Rdata<'a> {
    pub fn from(typ: Type, raw: &'a [u8]) -> Option<Rdata<'a>> {
        match typ {
            Type::A => {
                if raw.len() >= 4 {
                    Some(Rdata::A(&raw[0..4]))
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
            Type::AAAA => {
                if raw.len() >= 16 {
                    Some(Rdata::AAAA(&raw[0..16]))
                    /* Some(Rdata::AAAA([
                        raw[15], raw[14], raw[13], raw[12],
                        raw[11], raw[10], raw[9], raw[8],
                        raw[7], raw[6], raw[5], raw[4],
                        raw[3], raw[2], raw[1], raw[0],
                    ])) */
                } else {
                    None
                }
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
                        rd: true,
                        ra: false,
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

    #[test]
    fn test_response() {
        let resp = [
            0x24, 0x1a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x03,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x05,
            0x28, 0x39, 0x00, 0x12, 0x03, 0x77, 0x77, 0x77,
            0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
            0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0xc0, 0x2c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xe3,
            0x00, 0x04, 0x42, 0xf9, 0x59, 0x63, 0xc0, 0x2c,
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xe3,
            0x00, 0x04, 0x42, 0xf9, 0x59, 0x68];
        // println!("{:?}", parse_dns_message(&resp));

        // println!("{:?}", parse_dns_message_full(&resp));

        assert_eq!(
            parse_dns_message_full(&resp),
            IResult::Done(
                &b""[..],
                Message {
                    header: Header {
                        id: 9242,
                        qr: QR::Response,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: true,
                        ra: true,
                        rcode: Rcode::NoError,
                        qdcount: 1,
                        ancount: 3,
                        nscount: 0,
                        arcount: 0
                    },
                    questions: vec![
                        Query {
                            qname: DomainName::Labels(vec![
                                          &[119, 119, 119],
                                          &[103, 111, 111, 103, 108, 101],
                                          &[99, 111, 109]
                            ]),
                            qtype: Qtype::Type(Type::A),
                            qclass: Qclass::Class(Class::IN)
                        }
                    ],
                    answers: vec![
                        ResourceRecord {
                            name: DomainName::Labels(vec![
                                         &[119, 119, 119],
                                         &[103, 111, 111, 103, 108, 101],
                                         &[99, 111, 109]
                            ]),
                            typ: Type::Cname,
                            class: Class::IN,
                            ttl: 337977,
                            rdata: Rdata::Cname(
                                DomainName::Labels(vec![
                                       &[119, 119, 119],
                                       &[108],
                                       &[103, 111, 111, 103, 108, 101],
                                       &[99, 111, 109]
                                ]))
                        },
                        ResourceRecord {
                            name: DomainName::Labels(vec![
                                         &[119, 119, 119],
                                         &[108],
                                         &[103, 111, 111, 103, 108, 101],
                                         &[99, 111, 109]
                            ]),
                            typ: Type::A,
                            class: Class::IN,
                            ttl: 227,
                            rdata: Rdata::A(&[66, 249, 89, 99])
                        },
                        ResourceRecord {
                            name: DomainName::Labels(vec![
                                         &[119, 119, 119],
                                         &[108],
                                         &[103, 111, 111, 103, 108, 101],
                                         &[99, 111, 109]
                            ]),
                            typ: Type::A,
                            class: Class::IN,
                            ttl: 227,
                            rdata: Rdata::A(&[66, 249, 89, 104])
                        }
                    ],
                    authorities: vec![],
                    additional: vec![]
                }
            )
        );
    }

    #[test]
    fn dns_deref() {
        let msg = [
            160, 219, 129, 128, 0, 1, 0, 2,
            0, 0, 0, 0, 7, 97, 110, 100,
            114, 111, 105, 100, 7, 99, 108, 105,
            101, 110, 116, 115, 6, 103, 111, 111,
            103, 108, 101, 3, 99, 111, 109, 0,
            0, 1, 0, 1, 192, 12, 0, 5, 0,
            1, 0, 0, 0, 69, 0, 12, 7, 97,
            110, 100, 114, 111, 105, 100, 1, 108,
            192, 28, 192, 56, 0, 1, 0, 1,
            0, 0, 0, 69, 0, 4, 216, 58, 219,
            78
        ];
        assert_eq!(
            parse_dns_message_full(&msg),
            IResult::Done(
                &b""[..],
                Message {
                    header: Header {
                        id: 41179,
                        qr: QR::Response,
                        opcode: Opcode::Query,
                        aa: false,
                        tc: false,
                        rd: true,
                        ra: true,
                        rcode: Rcode::NoError,
                        qdcount: 1,
                        ancount: 2,
                        nscount: 0,
                        arcount: 0
                    },
                    questions: vec![
                        Query {
                            qname: DomainName::Labels(vec![
                                          &[97, 110, 100, 114, 111, 105, 100],
                                          &[99, 108, 105, 101, 110, 116, 115],
                                          &[103, 111, 111, 103, 108, 101],
                                          &[99, 111, 109]]),
                            qtype: Qtype::Type(Type::A),
                            qclass: Qclass::Class(Class::IN)
                        }
                    ],
                    answers: vec![
                        ResourceRecord {
                            name: DomainName::Labels(vec![
                                                     &[97, 110, 100, 114, 111, 105, 100],
                                                     &[99, 108, 105, 101, 110, 116, 115],
                                                     &[103, 111, 111, 103, 108, 101],
                                                     &[99, 111, 109]]),
                            typ: Type::Cname,
                            class: Class::IN,
                            ttl: 69,
                            rdata: Rdata::Cname(DomainName::Labels(vec![
                                                                   &[97, 110, 100, 114, 111, 105, 100],
                                                                   &[108],
                                                                   &[103, 111, 111, 103, 108, 101],
                                                                   &[99, 111, 109]]))
                        },
                        ResourceRecord {
                            name: DomainName::Labels(vec![
                                                     &[97, 110, 100, 114, 111, 105, 100],
                                                     &[108],
                                                     &[103, 111, 111, 103, 108, 101],
                                                     &[99, 111, 109]]),
                            typ: Type::A,
                            class: Class::IN,
                            ttl: 69,
                            rdata: Rdata::A(&[216, 58, 219, 78])
                        }
                    ],
                    authorities: vec![],
                    additional: vec![]
                })
        );
    }
}
