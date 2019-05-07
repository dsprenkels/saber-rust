use crate::params::*;
use core::ops::{Add, Mul, Shl, Shr};

/// Poly is equivalent to the reference implementation's `poly` type
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [u16; N],
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "[",)?;
        for c in self.coeffs.iter() {
            write!(f, "0x{:04x}, ", c)?;
        }
        write!(f, "]",)
    }
}

impl Add for Poly {
    type Output = Self;

    #[inline]
    fn add(self, rhs: Self) -> Poly {
        let Poly { coeffs: a } = self;
        let Poly { coeffs: b } = rhs;
        let mut c = [0_u16; N];

        for i in 0..N {
            c[i] = a[i].wrapping_add(b[i]);
        }
        Poly { coeffs: c }
    }
}

impl Add<u16> for Poly {
    type Output = Self;

    #[inline]
    fn add(self, rhs: u16) -> Poly {
        let Poly { mut coeffs } = self;
        for coeff in coeffs.iter_mut() {
            *coeff = coeff.wrapping_add(rhs);
        }
        Poly { coeffs }
    }
}

impl Mul for Poly {
    type Output = Self;

    #[inline]
    fn mul(self, rhs: Self) -> Poly {
        let Poly { coeffs: a } = self;
        let Poly { coeffs: b } = rhs;
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
        Poly { coeffs: c }
    }
}

impl Shl<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shl(self, rhs: u8) -> Self {
        let Poly { mut coeffs } = self;
        for coeff in coeffs.iter_mut() {
            *coeff <<= rhs;
        }
        Poly { coeffs }
    }
}

impl Shr<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Poly { mut coeffs } = self;
        for coeff in coeffs.iter_mut() {
            *coeff >>= rhs;
        }
        Poly { coeffs }
    }
}

impl<'a> From<&'a [u8; 416]> for Poly {
    /// This function implements BS2POL, as described in Algorithm 7
    fn from(bytes: &'a [u8; 416]) -> Self {
        let mut coeffs = [0; N];
        for idx in 0..(N / 8) {
            let bs = &bytes[13 * idx..13 * (idx + 1)];
            let cs = &mut coeffs[8 * idx..8 * (idx + 1)];

            cs[0] = u16::from(bs[0]) | (u16::from(bs[1]) << 8);
            cs[1] = (u16::from(bs[1]) >> 5) | (u16::from(bs[2]) << 3) | (u16::from(bs[3]) << 11);
            cs[2] = (u16::from(bs[3]) >> 2) | (u16::from(bs[4]) << 6);
            cs[3] = (u16::from(bs[4]) >> 7) | (u16::from(bs[5]) << 1) | (u16::from(bs[6]) << 9);
            cs[4] = (u16::from(bs[6]) >> 4) | (u16::from(bs[7]) << 4) | (u16::from(bs[8]) << 12);
            cs[5] = (u16::from(bs[8]) >> 1) | (u16::from(bs[9]) << 7);
            cs[6] = (u16::from(bs[9]) >> 6) | (u16::from(bs[10]) << 2) | (u16::from(bs[11]) << 10);
            cs[7] = (u16::from(bs[11]) >> 3) | (u16::from(bs[12]) << 5);
        }
        Poly { coeffs }
    }
}

impl<'a> Into<[u8; 13 * 256 / 8]> for &'a Poly {
    fn into(self) -> [u8; 13 * 256 / 8] {
        // XXX This function is currently still untested

        let Poly { coeffs } = self;
        let mut bytes = [0_u8; 13 * 256 / 8];
        for i in 0..32 {
            let cs = &coeffs[8 * i..8 * (i + 1)];
            let bs = &mut bytes[416 - 13 * (i + 1)..416 - 13 * i];

            bs[12] = (cs[0] >> 5) as u8;
            bs[11] = (cs[0] << 3) as u8 | (cs[1] >> 10) as u8;
            bs[10] = (cs[1] >> 2) as u8;
            bs[9] = (cs[1] << 6) as u8 | (cs[2] >> 7) as u8;
            bs[8] = (cs[2] << 1) as u8 | (cs[3] >> 12) as u8;
            bs[7] = (cs[3] >> 4) as u8;
            bs[6] = (cs[3] << 4) as u8 | (cs[4] >> 9) as u8;
            bs[5] = (cs[4] >> 1) as u8;
            bs[4] = (cs[4] << 7) as u8 | (cs[5] >> 6) as u8;
            bs[3] = (cs[5] << 2) as u8 | (cs[6] >> 11) as u8;
            bs[2] = (cs[6] >> 3) as u8;
            bs[1] = (cs[6] << 5) as u8 | (cs[7] >> 8) as u8;
            bs[0] = cs[7] as u8;
        }
        bytes
    }
}

impl Default for Poly {
    #[inline]
    fn default() -> Self {
        Poly { coeffs: [0; N] }
    }
}

impl Poly {
    #[inline]
    pub fn reduce(self, m: u16) -> Self {
        debug_assert!(
            m.is_power_of_two(),
            "m must be a power of two, not 0x{:02x}",
            m
        );
        let Poly { mut coeffs } = self;
        for coeff in coeffs.iter_mut() {
            *coeff &= m - 1;
        }
        Poly { coeffs }
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
                    c.coeffs[j], expected.coeffs[j],
                    "test case {} has failed; invalid value for j = {}",
                    i, j
                );
            }
        }
    }
}
