extern crate rand;
extern crate sha3;

mod params;
mod poly;
mod saber;

trait SaberImplementation {
    type Vector;
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
