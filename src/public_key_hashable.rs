/*
 * Copyright 2020 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use fluence_keypair::PublicKey;

use core::fmt;
use ref_cast::RefCast;
use serde::ser::Serializer;
use std::str::FromStr;
use std::{
    fmt::{Display, Formatter},
    hash::{Hash, Hasher},
};

/// Wrapper to use PublicKey in HashMap
#[derive(PartialEq, Eq, Debug, Clone, RefCast)]
#[repr(transparent)]
pub struct PublicKeyHashable(PublicKey);

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for PublicKeyHashable {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0.encode());
        state.finish();
    }

    fn hash_slice<H: Hasher>(data: &[Self], state: &mut H)
    where
        Self: Sized,
    {
        // TODO check for overflow
        let mut bytes: Vec<u8> = Vec::with_capacity(data.len() * 32);
        for d in data {
            bytes.extend_from_slice(&d.0.encode())
        }
        state.write(bytes.as_slice());
        state.finish();
    }
}

impl From<PublicKey> for PublicKeyHashable {
    fn from(pk: PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PublicKeyHashable> for PublicKey {
    fn from(pk: PublicKeyHashable) -> PublicKey {
        pk.0
    }
}

impl AsRef<PublicKey> for PublicKeyHashable {
    fn as_ref(&self) -> &PublicKey {
        &self.0
    }
}

impl AsRef<PublicKeyHashable> for PublicKey {
    fn as_ref(&self) -> &PublicKeyHashable {
        PublicKeyHashable::ref_cast(self)
    }
}

impl Display for PublicKeyHashable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", bs58::encode(self.0.encode()).into_string())
    }
}

impl FromStr for PublicKeyHashable {
    type Err = fluence_keypair::error::DecodingError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pk = PublicKey::from_base58(s)?;
        Ok(PublicKeyHashable::from(pk))
    }
}

impl serde::Serialize for PublicKeyHashable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0.encode())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKeyHashable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{Error, Visitor};

        struct PKVisitor;

        impl<'de> Visitor<'de> for PKVisitor {
            type Value = PublicKeyHashable;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("byte array or base58 string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                bs58::decode(s)
                    .into_vec()
                    .map_err(|err| Error::custom(format!("Invalid string '{s}': {err}")))
                    .and_then(|v| self.visit_bytes(v.as_slice()))
                    .map_err(|err: E| {
                        Error::custom(format!("Parsed string '{s}' as base58, but {err}"))
                    })
            }

            fn visit_bytes<E>(self, b: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let pk = PublicKey::decode(b)
                    .map_err(|err| Error::custom(format!("Invalid bytes {b:?}: {err}")))?;
                Ok(PublicKeyHashable::from(pk))
            }
        }

        deserializer.deserialize_str(PKVisitor)
    }
}
