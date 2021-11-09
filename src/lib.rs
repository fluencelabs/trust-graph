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

#![recursion_limit = "512"]
#![warn(rust_2018_idioms)]
#![deny(
    dead_code,
    nonstandard_style,
    unused_imports,
    unused_mut,
    unused_variables,
    unused_unsafe,
    unreachable_patterns
)]
#![allow(dead_code)]

mod certificate;
pub mod certificate_serde;
mod misc;
mod public_key_hashable;
mod revoke;
mod trust;
mod trust_graph;
mod trust_graph_storage;
mod trust_relation;

pub use crate::certificate::{Certificate, CertificateError};
pub use crate::misc::current_time;
pub use crate::public_key_hashable::PublicKeyHashable;
pub use crate::revoke::Revoke;
pub use crate::trust::{Trust, TrustError};
pub use crate::trust_graph::{TrustGraph, TrustGraphError, WeightFactor, MAX_WEIGHT_FACTOR};
pub use crate::trust_graph_storage::{Storage, StorageError};
pub use crate::trust_relation::{Auth, TrustRelation};
