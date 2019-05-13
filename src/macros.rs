#[macro_export]
macro_rules! byte_array_newtype {
    ($name:ident, $length:expr, $type:ty) => {
        #[derive(Clone)]
        struct $name($type);

        impl Default for $name {
            fn default() -> $name {
                $name([0; $length])
            }
        }

        impl Into<$type> for $name {
            fn into(self) -> $type {
                self.0
            }
        }

        impl AsRef<$type> for $name {
            fn as_ref(&self) -> &$type {
                &self.0
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl $name {
            pub fn as_slice(&self) -> &[u8] {
                self.as_ref()
            }
        }
    };
}
