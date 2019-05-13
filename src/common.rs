pub const HASHBYTES: usize = 32;
pub const KEYBYTES: usize = 32;
pub const MESSAGEBYTES: usize = 32;
pub const NOISE_SEEDBYTES: usize = 32;
pub const SEEDBYTES: usize = 32;
pub const CIPHERTEXT_BYTES: usize = 32;

__byte_array_newtype!(pub SharedSecret, KEYBYTES, [u8; KEYBYTES]);
__byte_array_newtype!(pub Ciphertext, CIPHERTEXT_BYTES, [u8; CIPHERTEXT_BYTES]);