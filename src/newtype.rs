#[doc(hidden)]
macro_rules! __byte_array_newtype {
    ($name:ident, $length:path, $type:ty) => {
        #[repr(C)]
        #[derive(Clone)]
        struct $name($type);

        __byte_array_newtype_impl!($name, $length, $type);
    };
    (pub $name:ident, $length:path, $type:ty) => {
        #[repr(C)]
        #[derive(Clone)]
        pub struct $name($type);

        __byte_array_newtype_impl!($name, $length, $type);
    };
    ($doc:meta, pub $name:ident, $length:path, $type:ty) => {
        #[repr(C)]
        #[derive(Clone)]
        #[$doc]
        pub struct $name($type);

        __byte_array_newtype_impl!($name, $length, $type);
    };
    (pub(crate) $name:ident, $length:path, $type:ty) => {
        #[repr(C)]
        #[derive(Clone)]
        pub(crate) struct $name($type);

        __byte_array_newtype_impl!($name, $length, $type);
    };
}

#[doc(hidden)]
macro_rules! __byte_array_newtype_impl {
    ($name:ident, $length:expr, $type:ty) => {
        impl $name {
            #[allow(unused)]
            pub fn into_bytes(self) -> $type {
                self.into()
            }

            #[allow(unused)]
            pub fn as_bytes(&self) -> &$type {
                self.as_ref()
            }

            #[allow(unused)]
            pub fn as_slice(&self) -> &[u8] {
                self.as_ref()
            }

            #[allow(unused)]
            pub fn as_mut_slice(&mut self) -> &mut [u8] {
                self.as_mut()
            }

            #[allow(unused)]
            pub fn from_bytes(bytes: &[u8]) -> Result<$name, crate::Error> {
                if bytes.len() != $length {
                    let err = crate::Error::BadLength {
                        name: stringify!($name),
                        actual: bytes.len(),
                        expected: $length,
                    };
                    return Err(err);
                }
                let mut result = Self::default();
                result.0.copy_from_slice(bytes);
                Ok(result)
            }
        }

        impl Default for $name {
            #[allow(unused)]
            fn default() -> $name {
                $name([0; $length])
            }
        }

        impl From<$type> for $name {
            #[allow(unused)]
            fn from(inner: $type) -> $name {
                $name(inner)
            }
        }

        impl Into<$type> for $name {
            #[allow(unused)]
            fn into(self) -> $type {
                self.0
            }
        }

        impl AsRef<$type> for $name {
            #[allow(unused)]
            fn as_ref(&self) -> &$type {
                &self.0
            }
        }

        impl AsMut<$type> for $name {
            #[allow(unused)]
            fn as_mut(&mut self) -> &mut $type {
                &mut self.0
            }
        }

        impl AsRef<[u8]> for $name {
            #[allow(unused)]
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl AsMut<[u8]> for $name {
            #[allow(unused)]
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }
    };
}
