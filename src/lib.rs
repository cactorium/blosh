#[macro_use]
extern crate nom;

// data link level parsers
// pub mod ethernet;

// transport level parsers
// pub mod tcp;

// application level parsers
pub mod dns;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
