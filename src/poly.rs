use secret_integers::*;

use crate::params::*;
use core::ops::{Add, Mul, Shl, Shr, Sub};

/// Poly is equivalent to the reference implementation's `poly` type
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Poly {
    pub(crate) coeffs: [U16; N],
}

impl Add for Poly {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Poly {
        for (coeff, other) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *coeff += *other;
        }
        self
    }
}

impl Add<U16> for Poly {
    type Output = Self;

    fn add(mut self, rhs: U16) -> Poly {
        for coeff in self.coeffs.iter_mut() {
            *coeff += rhs;
        }
        self
    }
}

impl Sub for Poly {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Poly {
        for (coeff, other) in self.coeffs.iter_mut().zip(rhs.coeffs.iter()) {
            *coeff -= *other;
        }
        self
    }
}

impl Sub<U16> for Poly {
    type Output = Self;

    fn sub(mut self, rhs: U16) -> Poly {
        for coeff in self.coeffs.iter_mut() {
            *coeff -= rhs;
        }
        self
    }
}

impl Mul for Poly {
    type Output = Self;

    fn mul(self, rhs: Self) -> Poly {
        let Poly { coeffs: a } = self;
        let Poly { coeffs: b } = rhs;
        let mut c = [U16::from(0); N];
        for i in 0..N {
            // These limbs do not pass the ring's degree
            for j in 0..N - i {
                c[(i + j)] += a[i] * b[j];
            }

            // These limbs pass the ring's degree and must be reduced modulo x^256 + 1
            for j in N - i..b.len() {
                c[(i + j) - N] -= a[i] * b[j];
            }
        }
        Poly { coeffs: c }
    }
}

impl Shl<u32> for Poly {
    type Output = Self;

    fn shl(mut self, rhs: u32) -> Self {
        for coeff in self.coeffs.iter_mut() {
            *coeff <<= rhs;
        }
        self
    }
}

impl Shr<u32> for Poly {
    type Output = Self;

    fn shr(mut self, rhs: u32) -> Self {
        for coeff in self.coeffs.iter_mut() {
            *coeff >>= rhs;
        }
        self
    }
}

impl Default for Poly {
    fn default() -> Self {
        Poly {
            coeffs: [0.into(); N],
        }
    }
}

impl Poly {
    pub(crate) fn reduce(mut self, m: u16) -> Self {
        debug_assert!(
            m.is_power_of_two(),
            "m must be a power of two, not 0x{:02x}",
            m
        );
        for coeff in self.coeffs.iter_mut() {
            *coeff &= U16::from(m - 1);
        }
        self
    }

    /// This function implements BS2POLq, as described in Algorithm 7
    pub(crate) fn from_bytes_13bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 13 * 256 / 8);
        let mut poly = Poly::default();
        for (bs, cs) in bytes.chunks_exact(13).zip(poly.coeffs.chunks_exact_mut(8)) {
            // In this functions, we do not have to mask the loaded values s.t. they are <2^16,
            // because 2^16 ≡ 0, as such all overloaded bits are equivalent to 0.
            cs[0] = U16::from(U8::from(bs[0])) | (U16::from(U8::from(bs[1])) << 8);
            cs[1] = (U16::from(U8::from(bs[1])) >> 5)
                | (U16::from(U8::from(bs[2])) << 3)
                | (U16::from(U8::from(bs[3])) << 11);
            cs[2] = (U16::from(U8::from(bs[3])) >> 2) | (U16::from(U8::from(bs[4])) << 6);
            cs[3] = (U16::from(U8::from(bs[4])) >> 7)
                | (U16::from(U8::from(bs[5])) << 1)
                | (U16::from(U8::from(bs[6])) << 9);
            cs[4] = (U16::from(U8::from(bs[6])) >> 4)
                | (U16::from(U8::from(bs[7])) << 4)
                | (U16::from(U8::from(bs[8])) << 12);
            cs[5] = (U16::from(U8::from(bs[8])) >> 1) | (U16::from(U8::from(bs[9])) << 7);
            cs[6] = (U16::from(U8::from(bs[9])) >> 6)
                | (U16::from(U8::from(bs[10])) << 2)
                | (U16::from(U8::from(bs[11])) << 10);
            cs[7] = (U16::from(U8::from(bs[11])) >> 3) | (U16::from(U8::from(bs[12])) << 5);
        }
        for coeff in poly.coeffs.iter_mut() {
            *coeff &= 0x1FFF.into();
        }
        poly
    }

    /// This function implements BS2POLp, as described in Algorithm 11
    pub(crate) fn from_bytes_10bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 10 * 256 / 8);
        let mut poly = Poly::default();
        for (bs, cs) in bytes.chunks_exact(5).zip(poly.coeffs.chunks_exact_mut(4)) {
            cs[0] = U16::from(U8::from(bs[0])) & 0xFF.into()
                | (U16::from(U8::from(bs[1]) & 0x03.into()) << 8);
            cs[1] = ((U16::from(U8::from(bs[1])) >> 2) & 0x3F.into())
                | (U16::from(U8::from(bs[2]) & 0x0F.into()) << 6);
            cs[2] = ((U16::from(U8::from(bs[2])) >> 4) & 0x0F.into())
                | (U16::from(U8::from(bs[3]) & 0x3F.into()) << 4);
            cs[3] = ((U16::from(U8::from(bs[3])) >> 6) & 0x03.into())
                | (U16::from(U8::from(bs[4])) << 2);
        }
        poly
    }

    /// This function mirrors the refererence implementation's `SABER_un_pack6bit` function
    pub(crate) fn from_bytes_6bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 6 * 256 / 8);
        let mut poly = Poly::default();

        for (bs, cs) in bytes.chunks_exact(3).zip(poly.coeffs.chunks_exact_mut(4)) {
            cs[0] = U16::from(U8::from(bs[0]) & 0x3F.into());
            cs[1] = U16::from((U8::from(bs[0]) >> 6) & 0x03.into())
                | U16::from((U8::from(bs[1]) & 0x0F.into()) << 2);
            cs[2] = U16::from((U8::from(bs[1]) >> 4) & 0x0F.into())
                | U16::from((U8::from(bs[2]) & 0x03.into()) << 4);
            cs[3] = U16::from(U8::from(bs[2]) >> 2);
        }
        poly
    }

    /// This function mirrors the refererence implementation's `SABER_un_pack4bit` function
    pub(crate) fn from_bytes_4bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 4 * 256 / 8);
        let mut poly = Poly::default();
        for (b, cs) in bytes.iter().zip(poly.coeffs.chunks_exact_mut(2)) {
            cs[0] = U16::from(U8::from(*b)) & 0x0F.into();
            cs[1] = U16::from(U8::from(*b)) >> 4;
        }
        poly
    }

    /// This function mirrors the refererence implementation's `SABER_un_pack3bit` function
    pub(crate) fn from_bytes_3bit(bytes: &[u8]) -> Self {
        debug_assert_eq!(bytes.len(), 3 * 256 / 8);
        let mut poly = Poly::default();
        for (bs, cs) in bytes.chunks_exact(3).zip(poly.coeffs.chunks_exact_mut(8)) {
            cs[0] = U16::from(U8::from(bs[0]) & 0x07.into());
            cs[1] = U16::from((U8::from(bs[0]) >> 3) & 0x07.into());
            cs[2] = U16::from((U8::from(bs[0]) >> 6) & 0x03.into())
                | U16::from((U8::from(bs[1]) & 0x01.into()) << 2);
            cs[3] = U16::from((U8::from(bs[1]) >> 1) & 0x07.into());
            cs[4] = U16::from((U8::from(bs[1]) >> 4) & 0x07.into());
            cs[5] = U16::from((U8::from(bs[1]) >> 7) & 0x01.into())
                | U16::from((U8::from(bs[2]) & 0x03.into()) << 1);
            cs[6] = U16::from((U8::from(bs[2]) >> 2) & 0x07.into());
            cs[7] = U16::from((U8::from(bs[2]) >> 5) & 0x07.into());
        }
        poly
    }

    /// This function implements MSG2POLp, as described in Algorithm 15
    pub(crate) fn from_msg(msg: &[u8]) -> Self {
        debug_assert_eq!(msg.len(), MESSAGEBYTES);
        let mut m_poly = Poly::default();
        for (b, coeffs_chunk) in msg.iter().zip(m_poly.coeffs.chunks_exact_mut(8)) {
            for (idx, coeff) in coeffs_chunk.iter_mut().enumerate() {
                *coeff =
                    U16::from((U8::from(*b) >> (idx as u32)) & 0x01.into()) << MSG2POL_CONST.into();
            }
        }
        m_poly
    }

    /// This function implements POLq2BS, as described in Algorithm 8
    pub(crate) fn read_bytes_13bit(self, declassified_bytes: &mut [u8]) {
        debug_assert_eq!(declassified_bytes.len(), 13 * 256 / 8);
        let mut bytes = [U8::from(0); 13 * 256 / 8];
        for (cs, bs) in self.coeffs.chunks_exact(8).zip(bytes.chunks_exact_mut(13)) {
            bs[0] = U8::from(cs[0] & 0xFF.into());
            bs[1] = U8::from((cs[0] >> 8) & 0x1F.into()) | U8::from((cs[1] & 0x07.into()) << 5);
            bs[2] = U8::from((cs[1] >> 3) & 0xFF.into());
            bs[3] = U8::from((cs[1] >> 11) & 0x03.into()) | U8::from((cs[2] & 0x3F.into()) << 2);
            bs[4] = U8::from((cs[2] >> 6) & 0x7F.into()) | U8::from((cs[3] & 0x01.into()) << 7);
            bs[5] = U8::from((cs[3] >> 1) & 0xFF.into());
            bs[6] = U8::from((cs[3] >> 9) & 0x0F.into()) | U8::from((cs[4] & 0x0F.into()) << 4);
            bs[7] = U8::from((cs[4] >> 4) & 0xFF.into());
            bs[8] = U8::from((cs[4] >> 12) & 0x01.into()) | U8::from((cs[5] & 0x7F.into()) << 1);
            bs[9] = U8::from((cs[5] >> 7) & 0x3F.into()) | U8::from((cs[6] & 0x03.into()) << 6);
            bs[10] = U8::from((cs[6] >> 2) & 0xFF.into());
            bs[11] = U8::from((cs[6] >> 10) & 0x07.into()) | U8::from((cs[7] & 0x1F.into()) << 3);
            bs[12] = U8::from((cs[7] >> 5) & 0xFF.into());
        }
        crate::generic::declassify_bytes(declassified_bytes, &bytes);
    }

    /// This function implements POLp2BS, as described in Algorithm 12
    pub(crate) fn read_bytes_10bit(self, declassified_bytes: &mut [u8]) {
        debug_assert_eq!(declassified_bytes.len(), 10 * 256 / 8);
        let mut bytes = [U8::from(0); 10 * 256 / 8];
        for (cs, bs) in self.coeffs.chunks_exact(4).zip(bytes.chunks_exact_mut(5)) {
            bs[0] = U8::from(cs[0] & 0xFF.into());
            bs[1] = U8::from((cs[0] >> 8) & 0x03.into()) | U8::from((cs[1] & 0x3F.into()) << 2);
            bs[2] = U8::from((cs[1] >> 6) & 0x0F.into()) | U8::from((cs[2] & 0x0F.into()) << 4);
            bs[3] = U8::from((cs[2] >> 4) & 0x3F.into()) | U8::from((cs[3] & 0x03.into()) << 6);
            bs[4] = U8::from((cs[3] >> 2) & 0xFF.into());
        }
        crate::generic::declassify_bytes(declassified_bytes, &bytes);
    }

    /// This function mirrors the refererence implementation's `SABER_pack_6bit` function
    pub(crate) fn read_bytes_6bit(self, declassified_bytes: &mut [u8]) {
        debug_assert_eq!(declassified_bytes.len(), 6 * 256 / 8);
        let mut bytes = [U8::from(0); 6 * 256 / 8];
        for (cs, bs) in self.coeffs.chunks_exact(4).zip(bytes.chunks_exact_mut(3)) {
            bs[0] = U8::from(cs[0] & 0x03F.into()) | U8::from((cs[1] & 0x03.into()) << 6);
            bs[1] = U8::from((cs[1] >> 2) & 0x0F.into()) | U8::from((cs[2] & 0x0F.into()) << 4);
            bs[2] = U8::from((cs[2] >> 4) & 0x03.into()) | U8::from((cs[3] & 0x3F.into()) << 2);
        }
        crate::generic::declassify_bytes(declassified_bytes, &bytes);
    }

    /// This function mirrors the refererence implementation's `SABER_pack_4bit` function
    pub(crate) fn read_bytes_4bit(self, declassified_bytes: &mut [u8]) {
        debug_assert_eq!(declassified_bytes.len(), 4 * 256 / 8);
        let mut bytes = [U8::from(0); 4 * 256 / 8];
        for (cs, b) in self.coeffs.chunks_exact(2).zip(bytes.iter_mut()) {
            *b = U8::from(cs[0] & 0x0F.into()) | U8::from((cs[1] & 0x0F.into()) << 4);
        }
        crate::generic::declassify_bytes(declassified_bytes, &bytes);
    }

    /// This function mirrors the refererence implementation's `SABER_pack_3bit` function
    pub(crate) fn read_bytes_3bit(self, declassified_bytes: &mut [u8]) {
        debug_assert_eq!(declassified_bytes.len(), 3 * 256 / 8);
        let mut bytes = [U8::from(0); 3 * 256 / 8];
        for (cs, bs) in self.coeffs.chunks_exact(8).zip(bytes.chunks_exact_mut(3)) {
            bs[0] = U8::from(cs[0] & 0x07.into())
                | U8::from((cs[1] & 0x07.into()) << 3)
                | U8::from((cs[2] & 0x03.into()) << 6);
            bs[1] = U8::from((cs[2] >> 2) & 0x01.into())
                | U8::from((cs[3] & 0x07.into()) << 1)
                | U8::from((cs[4] & 0x07.into()) << 4)
                | U8::from(((cs[5] >> 2) & 0x01.into()) << 7);
            bs[2] = U8::from((cs[5] >> 1) & 0x03.into())
                | U8::from((cs[6] & 0x07.into()) << 2)
                | U8::from((cs[7] & 0x07.into()) << 5);
        }
        crate::generic::declassify_bytes(declassified_bytes, &bytes);
    }

    /// This function implements POL2MSG, which it seems they forgot to include in the submission
    /// document
    pub(crate) fn read_bytes_msg(self, declassified_msg: &mut [u8]) {
        debug_assert_eq!(declassified_msg.len(), MESSAGEBYTES);
        let mut msg = [U8::from(0); MESSAGEBYTES];
        for (coeffs_chunk, b) in self.coeffs.chunks_exact(8).zip(msg.iter_mut()) {
            *b = U8::from(0);
            for (idx, coeff) in coeffs_chunk.iter().enumerate() {
                *b |= U8::from(*coeff) << (idx as u32);
            }
        }
        crate::generic::declassify_bytes(declassified_msg, &msg);
    }
}
