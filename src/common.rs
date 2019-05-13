use crate::Error as SaberError;

// Universal constants
pub const N: usize = 256;
pub const Q: u16 = 8192;
pub const P: u16 = 1024;

pub const EPS_Q: u8 = 13;
pub const EPS_P: u8 = 10;

// Buffer lengths
pub const COINBYTES: usize = 32;
pub const HASHBYTES: usize = 32;
pub const KEYBYTES: usize = 32;
pub const MESSAGEBYTES: usize = 32;
pub const NOISE_SEEDBYTES: usize = 32;
pub const SEEDBYTES: usize = 32;
pub const CIPHERTEXT_BYTES: usize = 32;

#[derive(Clone)]
pub struct SharedSecret {
    pub sessionkey_cca: [u8; KEYBYTES],
}

impl SharedSecret {
    pub fn to_bytes(&self) -> [u8; KEYBYTES] {
        self.sessionkey_cca
    }

    pub fn as_bytes(&self) -> &[u8; KEYBYTES] {
        &self.sessionkey_cca
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SharedSecret, SaberError> {
        unimplemented!()
    }
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone)]
pub struct Ciphertext {
    ciphertext_cca: [u8; CIPHERTEXT_BYTES],
}

impl Ciphertext {
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        unimplemented!()
    }

    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_BYTES] {
        &self.ciphertext_cca
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Ciphertext, SaberError> {
        unimplemented!()
    }
}
