use crate::params::*;
use core::ops::{Add, Mul, Shl, Shr};

/// Poly is equivalent to the reference implementation's `poly` type
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Poly(pub [u16; N]);

impl Add for Poly {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Poly {
        let Poly(a) = self;
        let Poly(b) = rhs;
        let mut c = [0_u16; N];

        for i in 0..N {
            c[i] = a[i].wrapping_add(b[i]);
        }
        Poly(c)
    }
}

impl Add<u16> for Poly {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Poly {
        let Poly(mut poly) = self;
        for idx in 0..N {
            poly[idx] = poly[idx].wrapping_add(rhs);
        }
        Poly(poly)
    }
}

impl Mul for Poly {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Poly {
        let Poly(a) = self;
        let Poly(b) = rhs;
        let mut c = [0_u16; N];
        for i in 0..N {
            // These limbs do not pass the ring's degree
            for j in 0..N - i {
                c[(i + j)] = c[(i + j)].wrapping_add(a[i].wrapping_mul(b[j]));
            }

            // These limbs pass the ring's degree and must be reduced modulo x^256 + 1
            for j in N - i..b.len() {
                c[(i + j) - N] = c[(i + j) - N].wrapping_sub(a[i].wrapping_mul(b[j]));
            }
        }
        Poly(c)
    }
}

impl Shl<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shl(self, rhs: u8) -> Self {
        let Poly(mut poly) = self;
        for i in 0..N {
            poly[i] = poly[i] << rhs;
        }
        Poly(poly)
    }
}

impl Shr<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Poly(mut poly) = self;
        for i in 0..N {
            poly[i] = poly[i] >> rhs;
        }
        Poly(poly)
    }
}

impl<'a> From<&'a [u8]> for Poly {
    /// This function implements BS2POL, as described in Algorithm 7
    fn from(bs: &'a [u8]) -> Self {
        assert_eq!(bs.len(), 416, "bad input length");
        let bs_at = |idx| u16::from(bs[idx]);
        let mut poly = [0_u16; N];
        for i in 0..bs.len() / 13 {
            let offset = 416 - 13 * i;
            poly[8 * i + 0] = (bs_at(offset - 1) << 5) | (bs_at(offset - 2) >> 3);
            poly[8 * i + 1] =
                (bs_at(offset - 2) << 10) | (bs_at(offset - 3) << 2) | (bs_at(offset - 4) >> 6);
            poly[8 * i + 2] = (bs_at(offset - 4) << 7) | (bs_at(offset - 5) >> 1);
            poly[8 * i + 3] =
                (bs_at(offset - 5) << 12) | (bs_at(offset - 6) << 4) | (bs_at(offset - 7) >> 4);
            poly[8 * i + 4] =
                (bs_at(offset - 7) << 9) | (bs_at(offset - 8) << 1) | (bs_at(offset - 9) >> 7);
            poly[8 * i + 5] = (bs_at(offset - 9) << 6) | (bs_at(offset - 10) >> 2);
            poly[8 * i + 6] =
                (bs_at(offset - 10) << 11) | (bs_at(offset - 11) << 3) | (bs_at(offset - 12) >> 5);
            poly[8 * i + 7] = (bs_at(offset - 12) << 8) | bs_at(offset - 13);
        }
        Poly(poly)
    }
}

impl<'a> Into<[u8; 13 * 256 / 8]> for &'a Poly {
    fn into(self) -> [u8; 13 * 256 / 8] {
        let Poly(poly) = self;
        let mut bs = [0_u8; 13 * 256 / 8];
        for i in 0..32 {
            let offset = 416 - 13 * i;
            bs[offset - 1] = (poly[8 * i + 0] >> 5) as u8;
            bs[offset - 2] = (poly[8 * i + 0] << 3) as u8 | (poly[8 * i + 1] >> 10) as u8;
            bs[offset - 3] = (poly[8 * i + 1] >> 2) as u8;
            bs[offset - 4] = (poly[8 * i + 1] << 6) as u8 | (poly[8 * i + 2] >> 7) as u8;
            bs[offset - 5] = (poly[8 * i + 2] << 1) as u8 | (poly[8 * i + 3] >> 12) as u8;
            bs[offset - 6] = (poly[8 * i + 3] >> 4) as u8;
            bs[offset - 7] = (poly[8 * i + 3] << 4) as u8 | (poly[8 * i + 4] >> 9) as u8;
            bs[offset - 8] = (poly[8 * i + 4] >> 1) as u8;
            bs[offset - 9] = (poly[8 * i + 4] << 7) as u8 | (poly[8 * i + 5] >> 6) as u8;
            bs[offset - 10] = (poly[8 * i + 5] << 2) as u8 | (poly[8 * i + 6] >> 11) as u8;
            bs[offset - 11] = (poly[8 * i + 6] >> 3) as u8;
            bs[offset - 12] = (poly[8 * i + 6] << 5) as u8 | (poly[8 * i + 7] >> 8) as u8;
            bs[offset - 13] = poly[8 * i + 7] as u8;
        }
        bs
    }
}

impl Poly {
    #[inline]
    pub fn new() -> Self {
        Poly([0; N])
    }

    #[inline]
    pub fn reduce(self, m: u16) -> Self {
        debug_assert!(
            m.is_power_of_two(),
            "m must be a power of two, not 0x{:02x}",
            m
        );
        let mut c = self.0;
        for i in 0..N {
            c[i] &= m - 1;
        }
        Poly(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // This file defines random tests in `POLY_MUL_RANDOM_TESTS`
    const POLY_MUL_RANDOM_TESTS: [(Poly, Poly, Poly); 100] =
        include!("testdata/poly_mul_random_tests.in");

    #[test]
    fn poly_mul_random() {
        for (i, test) in POLY_MUL_RANDOM_TESTS.iter().enumerate() {
            let (a, b, expected) = test;
            let c = (*a * *b).reduce(Q);

            // We need this loop if we don't want to impl Debug on [u16; 256] ourselves
            for j in 0..N {
                assert_eq!(
                    c.0[j], expected.0[j],
                    "test case {} has failed; invalid value for j = {}",
                    i, j
                );
            }
        }
    }
}
