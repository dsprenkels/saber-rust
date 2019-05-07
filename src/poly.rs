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
        for idx in 0..N {
            coeffs[idx] = coeffs[idx].wrapping_add(rhs);
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
        for i in 0..N {
            coeffs[i] = coeffs[i] << rhs;
        }
        Poly { coeffs }
    }
}

impl Shr<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shr(self, rhs: u8) -> Self {
        let Poly { mut coeffs } = self;
        for i in 0..N {
            coeffs[i] >>= rhs;
        }
        Poly { coeffs }
    }
}

impl<'a> From<&'a [u8]> for Poly {
    /// This function implements BS2POL, as described in Algorithm 7
    fn from(bs: &'a [u8]) -> Self {
        assert_eq!(bs.len(), 416, "bad input length");
        let bs_at = |idx| u16::from(bs[idx]);
        let mut coeffs = [0_u16; N];
        for i in 0..bs.len() / 13 {
            let offset = 416 - 13 * i;
            coeffs[8 * i + 0] = (bs_at(offset - 1) << 5) | (bs_at(offset - 2) >> 3);
            coeffs[8 * i + 1] =
                (bs_at(offset - 2) << 10) | (bs_at(offset - 3) << 2) | (bs_at(offset - 4) >> 6);
            coeffs[8 * i + 2] = (bs_at(offset - 4) << 7) | (bs_at(offset - 5) >> 1);
            coeffs[8 * i + 3] =
                (bs_at(offset - 5) << 12) | (bs_at(offset - 6) << 4) | (bs_at(offset - 7) >> 4);
            coeffs[8 * i + 4] =
                (bs_at(offset - 7) << 9) | (bs_at(offset - 8) << 1) | (bs_at(offset - 9) >> 7);
            coeffs[8 * i + 5] = (bs_at(offset - 9) << 6) | (bs_at(offset - 10) >> 2);
            coeffs[8 * i + 6] =
                (bs_at(offset - 10) << 11) | (bs_at(offset - 11) << 3) | (bs_at(offset - 12) >> 5);
            coeffs[8 * i + 7] = (bs_at(offset - 12) << 8) | bs_at(offset - 13);
        }
        Poly { coeffs }
    }
}

impl<'a> Into<[u8; 13 * 256 / 8]> for &'a Poly {
    fn into(self) -> [u8; 13 * 256 / 8] {
        let Poly { coeffs } = self;
        let mut bs = [0_u8; 13 * 256 / 8];
        for i in 0..32 {
            let offset = 416 - 13 * i;
            bs[offset - 1] = (coeffs[8 * i + 0] >> 5) as u8;
            bs[offset - 2] = (coeffs[8 * i + 0] << 3) as u8 | (coeffs[8 * i + 1] >> 10) as u8;
            bs[offset - 3] = (coeffs[8 * i + 1] >> 2) as u8;
            bs[offset - 4] = (coeffs[8 * i + 1] << 6) as u8 | (coeffs[8 * i + 2] >> 7) as u8;
            bs[offset - 5] = (coeffs[8 * i + 2] << 1) as u8 | (coeffs[8 * i + 3] >> 12) as u8;
            bs[offset - 6] = (coeffs[8 * i + 3] >> 4) as u8;
            bs[offset - 7] = (coeffs[8 * i + 3] << 4) as u8 | (coeffs[8 * i + 4] >> 9) as u8;
            bs[offset - 8] = (coeffs[8 * i + 4] >> 1) as u8;
            bs[offset - 9] = (coeffs[8 * i + 4] << 7) as u8 | (coeffs[8 * i + 5] >> 6) as u8;
            bs[offset - 10] = (coeffs[8 * i + 5] << 2) as u8 | (coeffs[8 * i + 6] >> 11) as u8;
            bs[offset - 11] = (coeffs[8 * i + 6] >> 3) as u8;
            bs[offset - 12] = (coeffs[8 * i + 6] << 5) as u8 | (coeffs[8 * i + 7] >> 8) as u8;
            bs[offset - 13] = coeffs[8 * i + 7] as u8;
        }
        bs
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

    #[inline]
    pub fn from_bytes_q(bytes: &[u8]) -> Self {
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
