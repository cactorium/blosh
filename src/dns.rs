use nom::{be_u8, be_u16, be_u32};

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

pub struct Z;

impl Z {
    fn from(i: u16) -> Option<Z> {
        match i {
            0 => Some(Z),
            _ => None,
        }
    }
}

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

pub struct ResourceRecord<'a> {
    pub name: DomainName<'a>,
    pub typ: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata: &'a [u8],
}
named!(resource_record<ResourceRecord>,
    do_parse!(
        name: domain_name >>
        typ: parse_type >>
        class: parse_class >>
        ttl: be_u32 >>
        rdlen: be_u16 >>
        rdata: take!(rdlen) >>
        (ResourceRecord {
            name: name,
            typ: typ,
            class: class,
            ttl: ttl,
            rdata: rdata,
        })
    )
);

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

