use crate::public_key_hashable::PublicKeyHashable as PK;
use crate::revoke::Revocation;
use crate::trust_graph::WeightFactor;
use crate::trust_relation::{Auth, TrustRelation};
use std::fmt::Display;
use std::time::Duration;

pub trait StorageError: std::error::Error + Display {}

pub trait Storage {
    type Error: StorageError + 'static;

    fn get_relation(
        &self,
        issued_for: &PK,
        issued_by: &PK,
    ) -> Result<Option<TrustRelation>, Self::Error>;

    fn get_authorizations(&self, issued_for: &PK) -> Result<Vec<Auth>, Self::Error>;
    fn get_revocations(&self, issued_for: &PK) -> Result<Vec<Revocation>, Self::Error>;

    fn insert(&mut self, node: TrustRelation) -> Result<(), Self::Error>;

    fn get_root_weight_factor(&self, pk: &PK) -> Result<Option<WeightFactor>, Self::Error>;
    fn set_root_weight_factor(
        &mut self,
        pk: PK,
        weight_factor: WeightFactor,
    ) -> Result<(), Self::Error>;
    fn root_keys(&self) -> Result<Vec<PK>, Self::Error>;
    fn revoke(&mut self, revocation: Revocation) -> Result<(), Self::Error>;
    fn update_auth(&mut self, auth: Auth, cur_time: Duration) -> Result<(), Self::Error>;
    fn remove_expired(&mut self, current_time: Duration) -> Result<(), Self::Error>;
}
