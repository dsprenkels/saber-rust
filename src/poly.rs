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
    fn add(mut self, rhs: Self) -> Poly {
        for (coeff, other) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *coeff = coeff.wrapping_add(*other);
        }
        self
    }
}

impl Add<u16> for Poly {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: u16) -> Poly {
        for coeff in self.coeffs.iter_mut() {
            *coeff = coeff.wrapping_add(rhs);
        }
        self
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
    fn shl(mut self, rhs: u8) -> Self {
        for coeff in self.coeffs.iter_mut() {
            *coeff <<= rhs;
        }
        self
    }
}

impl Shr<u8> for Poly {
    type Output = Self;

    #[inline]
    fn shr(mut self, rhs: u8) -> Self {
        for coeff in self.coeffs.iter_mut() {
            *coeff >>= rhs;
        }
        self
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
    pub fn reduce(mut self, m: u16) -> Self {
        debug_assert!(
            m.is_power_of_two(),
            "m must be a power of two, not 0x{:02x}",
            m
        );
        for coeff in self.coeffs.iter_mut() {
            *coeff &= m - 1;
        }
        self
    }

    /// This function implements BS2POLq, as described in Algorithm 7
    pub fn from_bytes_13bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 13 * 256 / 8);
        let mut poly = Poly::default();
        for (bs, cs) in bytes.chunks_exact(13).zip(poly.coeffs.chunks_exact_mut(8)) {
            // In this functions, we do not have to mask the loaded values s.t. they are <2^16,
            // because 2^16 ≡ 0, as such all overloaded bits are equivalent to 0.
            cs[0] = u16::from(bs[0]) | (u16::from(bs[1]) << 8);
            cs[1] = (u16::from(bs[1]) >> 5) | (u16::from(bs[2]) << 3) | (u16::from(bs[3]) << 11);
            cs[2] = (u16::from(bs[3]) >> 2) | (u16::from(bs[4]) << 6);
            cs[3] = (u16::from(bs[4]) >> 7) | (u16::from(bs[5]) << 1) | (u16::from(bs[6]) << 9);
            cs[4] = (u16::from(bs[6]) >> 4) | (u16::from(bs[7]) << 4) | (u16::from(bs[8]) << 12);
            cs[5] = (u16::from(bs[8]) >> 1) | (u16::from(bs[9]) << 7);
            cs[6] = (u16::from(bs[9]) >> 6) | (u16::from(bs[10]) << 2) | (u16::from(bs[11]) << 10);
            cs[7] = (u16::from(bs[11]) >> 3) | (u16::from(bs[12]) << 5);
        }
        for coeff in poly.coeffs.iter_mut() {
            *coeff &= 0x1FFF;
        }
        poly
    }

    /// This function implements BS2POLp, as described in Algorithm 11
    pub fn from_bytes_10bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 10 * 256 / 8);
        let mut poly = Poly::default();
        for (bs, cs) in bytes.chunks_exact(5).zip(poly.coeffs.chunks_exact_mut(4)) {
            cs[0] = u16::from(bs[0]) & 0xFF | (u16::from(bs[1] & 0x03) << 8);
            cs[1] = ((u16::from(bs[1]) >> 2) & 0x3F) | (u16::from(bs[2] & 0x0F) << 6);
            cs[2] = ((u16::from(bs[2]) >> 4) & 0x0F) | (u16::from(bs[3] & 0x3F) << 4);
            cs[3] = ((u16::from(bs[3]) >> 6) & 0x03) | (u16::from(bs[4]) << 2);
        }
        poly
    }

    /// This function implements MSG2POLp, as described in Algorithm 15
    pub fn from_msg(msg: &[u8]) -> Self {
        debug_assert_eq!(msg.len(), MESSAGEBYTES);
        const MSG2POL_CONST: u8 = LOG_Q - 1;
        let mut m_poly = Poly::default();
        for (b, coeffs_chunk) in msg.iter().zip(m_poly.coeffs.chunks_exact_mut(8)) {
            for (idx, coeff) in coeffs_chunk.iter_mut().enumerate() {
                *coeff = u16::from((b >> idx) & 0x01) << MSG2POL_CONST;
            }
        }
        m_poly
    }

    /// This function implements POLq2BS, as described in Algorithm 8
    pub fn read_bytes_13bit(self, bs: &[u8]) {
        debug_assert_eq!(bs.len(), 416);
        unimplemented!()
    }

    /// This function implements POLp2BS, as described in Algorithm 12
    pub fn read_bytes_10bit(self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), 10 * 256 / 8);
        for (cs, bs) in self.coeffs.chunks_exact(4).zip(bytes.chunks_exact_mut(5)) {
            bs[0] = (cs[0] & 0xFF) as u8;
            bs[1] = ((cs[0] >> 8) & 0x03) as u8 | ((cs[1] & 0x3F) as u8) << 2;
            bs[2] = ((cs[1] >> 6) & 0x0F) as u8 | ((cs[2] & 0x0F) as u8) << 4;
            bs[3] = ((cs[2] >> 4) & 0x3F) as u8 | ((cs[3] & 0x03) as u8) << 6;
            bs[4] = ((cs[3] >> 2) & 0xFF) as u8;
        }
    }

    /// This function mirrors the refererence implementation's `SABER_pack_4bit` function
    pub fn read_bytes_4bit(self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), 4 * 256 / 8);

        for b in bytes.iter_mut() {
            *b = 0;
        }

        for (cs, b) in self.coeffs.chunks_exact(2).zip(bytes.iter_mut()) {
            *b = (cs[0] & 0x0F) as u8 | ((cs[1] & 0x0F) << 4) as u8;
        }
    }

    /// This function implements POL2MSG, which it seems they forgot to include in the submission
    /// document
    pub fn read_bytes_msg(self, msg: &mut [u8]) {
        debug_assert_eq!(msg.len(), MESSAGEBYTES);
        for (coeffs_chunk, b) in self.coeffs.chunks_exact(8).zip(msg.iter_mut()) {
            *b = 0;
            for (idx, coeff) in coeffs_chunk.iter().enumerate() {
                *b |= (*coeff as u8) << idx;
            }
        }
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
