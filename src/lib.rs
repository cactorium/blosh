#[macro_use]
extern crate nom;

// data link level parsers
// pub mod ethernet;

// internet level parsers
pub mod ipv4;
// pub mod ipv6;

// transport level parsers
pub mod tcp;
pub mod udp;

// application level parsers
pub mod dns;
// pub mod telnet;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
