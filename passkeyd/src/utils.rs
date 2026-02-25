// use std::ops::{Deref, DerefMut};

use ctap_types::serde::{cbor_serialize_to, ser::Writer};
use serde::Serialize;

pub struct CborVec(pub Vec<u8>);

impl CborVec {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_size_hint(hint: usize) -> Self {
        Self(Vec::with_capacity(hint))
    }
    pub fn take_inner(self) -> Vec<u8> {
        self.0
    }

    pub fn with_object<T>(obj: T, size_hint: usize) -> Self
    where
        T: Serialize,
    {
        let mut cbor_data = CborVec::with_size_hint(size_hint);
        cbor_serialize_to(&obj, &mut cbor_data).expect("Failed to translate to cbor");
        cbor_data
    }
}

impl Writer for CborVec {
    type Error = ctap_types::serde::Error;
    fn write_all(&mut self, buf: &[u8]) -> ctap_types::serde::Result<(), Self::Error> {
        self.0.extend_from_slice(buf);
        Ok(())
    }
}

// impl Deref for CborVec {
//     type Target = Vec<u8>;
//     fn deref(&self) -> &Self::Target {
//         &self.0
//     }
// }

// impl DerefMut for CborVec {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.0
//     }
// }

impl AsRef<[u8]> for CborVec {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
