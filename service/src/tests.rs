/*
 * Copyright 2021 Fluence Labs Limited
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

#[cfg(test)]
mod service_tests {
    marine_rs_sdk_test::include_test_env!("/marine_test_env.rs");
    use crate::error::ServiceError;
    use crate::storage_impl::DB_PATH;
    use crate::{TRUSTED_TIMESTAMP_FUNCTION_NAME, TRUSTED_TIMESTAMP_SERVICE_ID};
    use fluence_keypair::KeyPair;
    use libp2p_core::PeerId;
    use marine_rs_sdk::{CallParameters, SecurityTetraplet};
    use marine_test_env::trust_graph::{Certificate, Revoke, ServiceInterface, Trust};
    use rusqlite::Connection;
    use std::collections::HashMap;
    use std::time::{SystemTime, UNIX_EPOCH};

    static HOST_ID: &str = "some_host_id";

    struct Auth {
        issuer: PeerId,
        trust: Trust,
    }

    impl PartialEq for Trust {
        fn eq(&self, other: &Self) -> bool {
            self.expires_at == other.expires_at
                && self.issued_at == other.issued_at
                && self.issued_for == other.issued_for
                && self.signature == other.signature
                && self.sig_type == other.sig_type
        }
    }

    impl Eq for Trust {}

    fn current_time() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn clear_env() {
        let connection = Connection::open(DB_PATH).unwrap();

        connection
            .execute("DELETE FROM trust_relations", [])
            .unwrap();
        connection.execute("DELETE FROM roots", []).unwrap();
    }

    fn get_correct_timestamp_cp(arg_number: usize) -> CallParameters {
        get_correct_timestamp_cp_with_host_id(arg_number, HOST_ID.to_string())
    }

    fn get_correct_timestamp_cp_with_host_id(arg_number: usize, host_id: String) -> CallParameters {
        let mut cp = CallParameters {
            host_id: host_id.clone(),
            ..CallParameters::default()
        };

        for _ in 0..arg_number {
            cp.tetraplets.push(vec![]);
        }

        cp.tetraplets.push(vec![SecurityTetraplet {
            peer_pk: host_id,
            service_id: TRUSTED_TIMESTAMP_SERVICE_ID.to_string(),
            function_name: TRUSTED_TIMESTAMP_FUNCTION_NAME.to_string(),
            json_path: "".to_string(),
        }]);

        cp
    }

    fn add_root_peer_id(trust_graph: &mut ServiceInterface, peer_id: PeerId, weight_factor: u32) {
        let result = trust_graph.add_root(peer_id.to_base58(), weight_factor);
        assert!(result.success, "{}", result.error);
    }

    fn add_root_with_trust(
        trust_graph: &mut ServiceInterface,
        issuer_kp: &KeyPair,
        issued_at_sec: u64,
        expires_at_sec: u64,
        weight_factor: u32,
    ) -> Trust {
        let result = trust_graph.add_root(issuer_kp.get_peer_id().to_base58(), weight_factor);
        assert!(result.success, "{}", result.error);
        add_trust(
            trust_graph,
            issuer_kp,
            &issuer_kp.get_peer_id(),
            issued_at_sec,
            expires_at_sec,
        )
    }

    fn issue_trust(
        trust_graph: &mut ServiceInterface,
        issuer_kp: &KeyPair,
        issued_for: &PeerId,
        issued_at_sec: u64,
        expires_at_sec: u64,
    ) -> Trust {
        let result =
            trust_graph.get_trust_bytes(issued_for.to_base58(), expires_at_sec, issued_at_sec);
        assert!(result.success, "{}", result.error);

        let trust_bytes = issuer_kp.sign(&result.result).unwrap().to_vec().to_vec();
        let issue_result = trust_graph.issue_trust(
            issued_for.to_base58(),
            expires_at_sec,
            issued_at_sec,
            trust_bytes,
        );
        assert!(issue_result.success, "{}", issue_result.error);

        issue_result.trust
    }

    fn issue_root_trust(
        trust_graph: &mut ServiceInterface,
        issuer_kp: &KeyPair,
        issued_at_sec: u64,
        expires_at_sec: u64,
    ) -> Trust {
        issue_trust(
            trust_graph,
            issuer_kp,
            &issuer_kp.get_peer_id(),
            issued_at_sec,
            expires_at_sec,
        )
    }

    fn add_trust(
        trust_graph: &mut ServiceInterface,
        issuer_kp: &KeyPair,
        issued_for: &PeerId,
        issued_at_sec: u64,
        expires_at_sec: u64,
    ) -> Trust {
        let trust = issue_trust(
            trust_graph,
            issuer_kp,
            issued_for,
            issued_at_sec,
            expires_at_sec,
        );
        let add_trust_result = trust_graph.add_trust_cp(
            trust.clone(),
            issuer_kp.get_peer_id().to_base58(),
            issued_at_sec,
            get_correct_timestamp_cp(2),
        );

        assert!(add_trust_result.success, "{}", add_trust_result.error);

        trust
    }

    fn add_trust_checked(
        trust_graph: &mut ServiceInterface,
        trust: Trust,
        issuer_peer_id: PeerId,
        cur_time: u64,
    ) {
        let result = trust_graph.add_trust_cp(
            trust,
            issuer_peer_id.to_base58(),
            cur_time,
            get_correct_timestamp_cp(2),
        );
        assert!(result.success, "{}", result.error);
    }

    fn add_trusts(trust_graph: &mut ServiceInterface, trusts: &[Auth], cur_time: u64) {
        for auth in trusts.iter() {
            add_trust_checked(trust_graph, auth.trust.clone(), auth.issuer, cur_time);
        }
    }

    fn revoke(
        trust_graph: &mut ServiceInterface,
        issuer_kp: &KeyPair,
        revoked_peer_id: &PeerId,
        revoked_at_sec: u64,
    ) -> Revoke {
        let result = trust_graph.get_revoke_bytes(revoked_peer_id.to_base58(), revoked_at_sec);
        assert!(result.success, "{}", result.error);

        let revoke_bytes = issuer_kp.sign(&result.result).unwrap().to_vec().to_vec();
        let issue_result = trust_graph.issue_revocation(
            revoked_peer_id.to_base58(),
            issuer_kp.get_peer_id().to_base58(),
            revoked_at_sec,
            revoke_bytes,
        );
        assert!(issue_result.success, "{}", issue_result.error);

        let revoke_result = trust_graph.revoke_cp(
            issue_result.revoke.clone(),
            revoked_at_sec,
            get_correct_timestamp_cp(1),
        );

        assert!(revoke_result.success, "{}", revoke_result.error);

        issue_result.revoke
    }

    fn generate_trust_chain_with(
        trust_graph: &mut ServiceInterface,
        len: usize,
        // Map of index to keypair. These key pairs will be used in trust chains at the given indexes
        keys: HashMap<usize, KeyPair>,
        expires_at: u64,
        issued_at: u64,
    ) -> (Vec<KeyPair>, Vec<Auth>) {
        assert!(len > 2);

        let root_kp = KeyPair::generate_ed25519();
        let second_kp = KeyPair::generate_ed25519();

        let root_trust = issue_root_trust(trust_graph, &root_kp, issued_at, expires_at);
        let second_trust = issue_trust(
            trust_graph,
            &root_kp,
            &second_kp.get_peer_id(),
            issued_at,
            expires_at,
        );
        let mut chain = vec![
            Auth {
                issuer: root_kp.get_peer_id(),
                trust: root_trust,
            },
            Auth {
                issuer: root_kp.get_peer_id(),
                trust: second_trust,
            },
        ];

        let mut key_pairs = vec![root_kp, second_kp];

        for idx in 2..len {
            let kp = keys
                .get(&idx)
                .unwrap_or(&KeyPair::generate_ed25519())
                .clone();
            let previous_kp = &key_pairs[idx - 1];

            let trust = issue_trust(
                trust_graph,
                &previous_kp,
                &kp.get_peer_id(),
                issued_at,
                expires_at,
            );
            chain.push(Auth {
                issuer: previous_kp.get_peer_id(),
                trust,
            });
            key_pairs.push(kp);
        }

        (key_pairs, chain)
    }

    fn generate_trust_chain_with_len(
        trust_graph: &mut ServiceInterface,
        len: usize,
        keys: HashMap<usize, KeyPair>,
    ) -> (Vec<KeyPair>, Vec<Auth>) {
        let cur_time = current_time();
        let far_future = cur_time + 60;

        generate_trust_chain_with(trust_graph, len, keys, far_future, cur_time)
    }

    fn get_weight(trust_graph: &mut ServiceInterface, peer_id: PeerId, cur_time: u64) -> u32 {
        let result =
            trust_graph.get_weight_cp(peer_id.to_base58(), cur_time, get_correct_timestamp_cp(1));
        assert!(result.success, "{}", result.error);
        result.weight
    }

    fn get_all_certs(
        trust_graph: &mut ServiceInterface,
        issued_for: PeerId,
        cur_time: u64,
    ) -> Vec<Certificate> {
        let result = trust_graph.get_all_certs_cp(
            issued_for.to_base58(),
            cur_time,
            get_correct_timestamp_cp(1),
        );
        assert!(result.success, "{}", result.error);
        result.certificates
    }

    #[test]
    fn add_root_not_owner() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let cp = CallParameters {
            init_peer_id: "other_peer_id".to_string(),
            service_creator_peer_id: "some_peer_id".to_string(),
            ..CallParameters::default()
        };

        let some_peer_id = KeyPair::generate_ed25519().get_peer_id();
        let result = trust_graph.add_root_cp(some_peer_id.to_base58(), 0, cp);
        assert!(!result.success);
        assert_eq!(result.error, ServiceError::NotOwner.to_string());
    }

    #[test]
    fn add_root_owner() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let peer_id = "some_peer_id".to_string();

        let cp = CallParameters {
            init_peer_id: peer_id.clone(),
            service_creator_peer_id: peer_id,
            ..CallParameters::default()
        };

        let some_peer_id = KeyPair::generate_ed25519().get_peer_id();
        let result = trust_graph.add_root_cp(some_peer_id.to_base58(), 0, cp);
        assert!(result.success, "{}", result.error);
    }

    #[test]
    fn add_root_trust() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let root_peer_id = root_kp.get_peer_id();
        let expires_at_sec = 9999u64;
        let issued_at_sec = 0u64;

        add_root_peer_id(&mut trust_graph, root_kp.get_peer_id(), 4u32);

        let result =
            trust_graph.get_trust_bytes(root_peer_id.to_base58(), expires_at_sec, issued_at_sec);
        assert!(result.success, "{}", result.error);
        let trust_bytes = root_kp.sign(&result.result).unwrap().to_vec().to_vec();

        let issue_result = trust_graph.issue_trust(
            root_peer_id.to_base58(),
            expires_at_sec,
            issued_at_sec,
            trust_bytes,
        );
        assert!(issue_result.success, "{}", issue_result.error);

        let verify_result = trust_graph.verify_trust_cp(
            issue_result.trust.clone(),
            root_peer_id.to_base58(),
            100u64,
            get_correct_timestamp_cp(2),
        );

        assert!(verify_result.success, "{}", verify_result.error);

        let add_trust_result = trust_graph.add_trust_cp(
            issue_result.trust,
            root_peer_id.to_base58(),
            100u64,
            get_correct_timestamp_cp(2),
        );

        assert!(add_trust_result.success, "{}", add_trust_result.error);
        assert_eq!(
            get_weight(&mut trust_graph, root_peer_id, 100u64),
            add_trust_result.weight
        );
    }

    #[test]
    fn test_expired_root_trust() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let cur_time = 100u64;
        let root_expired_time = cur_time + 10000;
        add_root_with_trust(
            &mut trust_graph,
            &root_kp,
            cur_time,
            root_expired_time - 1,
            4,
        );

        let trust_kp = KeyPair::generate_ed25519();
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
            root_expired_time + 99999,
        );

        let root_weight = get_weight(&mut trust_graph, root_kp.get_peer_id(), cur_time);
        let trust_weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_eq!(root_weight / 2, trust_weight);

        let certs = get_all_certs(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_eq!(certs.len(), 1);

        // get all certs after root expiration
        let certs = get_all_certs(&mut trust_graph, trust_kp.get_peer_id(), root_expired_time);
        assert_eq!(certs.len(), 0);

        // check garbage collector
        let certs = get_all_certs(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn revoke_test() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let mut cur_time = 100u64;
        add_root_with_trust(&mut trust_graph, &root_kp, cur_time, cur_time + 9999, 4u32);

        let trust_kp = KeyPair::generate_ed25519();
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
            cur_time + 99999,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_ne!(weight, 0u32);

        cur_time += 1;
        revoke(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_eq!(weight, 0u32);
    }

    #[test]
    fn test_add_one_trust_to_cert_last() {
        let mut trust_graph = ServiceInterface::new();
        let (key_pairs, mut trusts) =
            generate_trust_chain_with_len(&mut trust_graph, 5, HashMap::new());
        let cur_time = current_time();

        let root_peer_id = key_pairs[0].get_peer_id();
        add_root_peer_id(&mut trust_graph, root_peer_id, 2);
        add_trusts(&mut trust_graph, &trusts, cur_time);

        let issued_by = key_pairs.last().unwrap().get_peer_id();
        let trust_kp = KeyPair::generate_ed25519();
        let issued_for = trust_kp.get_peer_id();
        let future = cur_time + 60;
        let trust = add_trust(
            &mut trust_graph,
            &key_pairs.last().unwrap(),
            &issued_for,
            cur_time,
            future,
        );
        trusts.push(Auth {
            issuer: issued_by,
            trust,
        });

        let previous_weight = get_weight(&mut trust_graph, issued_by, cur_time);
        assert_ne!(previous_weight, 0u32);

        let weight = get_weight(&mut trust_graph, issued_for, cur_time);
        assert_eq!(weight * 2, previous_weight);

        let certs = get_all_certs(&mut trust_graph, issued_for, cur_time);
        assert_eq!(certs.len(), 1);

        for (i, trust) in certs[0].chain.iter().enumerate() {
            assert_eq!(*trust, trusts[i].trust);
        }
    }

    #[test]
    fn test_expired_trust() {
        let mut trust_graph = ServiceInterface::new();
        let (key_pairs, mut trusts) =
            generate_trust_chain_with_len(&mut trust_graph, 5, HashMap::new());
        let cur_time = current_time();

        let root1_peer_id = key_pairs[0].get_peer_id();
        add_root_peer_id(&mut trust_graph, root1_peer_id, 2);
        add_trusts(&mut trust_graph, &trusts, cur_time);

        let issued_by = key_pairs.last().unwrap().get_peer_id();
        let trust_kp = KeyPair::generate_ed25519();
        let issued_for = trust_kp.get_peer_id();
        let expired_time = cur_time + 60;

        let trust = add_trust(
            &mut trust_graph,
            &key_pairs.last().unwrap(),
            &issued_for,
            cur_time,
            expired_time,
        );
        trusts.push(Auth {
            issuer: issued_by,
            trust,
        });

        let certs = get_all_certs(&mut trust_graph, issued_for, cur_time);
        assert_eq!(certs.len(), 1);
        for (i, trust) in certs[0].chain.iter().enumerate() {
            assert_eq!(*trust, trusts[i].trust);
        }

        let certs = get_all_certs(&mut trust_graph, issued_for, expired_time);
        assert_eq!(certs.len(), 0);

        // check garbage collector
        let certs = get_all_certs(&mut trust_graph, issued_for, cur_time);
        assert_eq!(certs.len(), 0);
    }

    #[test]
    fn test_get_one_cert() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let (key_pairs, trusts) =
            generate_trust_chain_with_len(&mut trust_graph, 5, HashMap::new());

        let cur_time = current_time();
        let root_peer_id = key_pairs[0].get_peer_id();
        add_root_peer_id(&mut trust_graph, root_peer_id, 1);

        for auth in trusts.iter() {
            add_trust_checked(&mut trust_graph, auth.trust.clone(), auth.issuer, cur_time);
        }

        let certs = trust_graph.get_all_certs_cp(
            key_pairs.last().unwrap().get_peer_id().to_base58(),
            cur_time,
            get_correct_timestamp_cp(1),
        );
        assert!(certs.success, "{}", certs.error);
        let certs = certs.certificates;
        assert_eq!(certs.len(), 1);

        for (i, trust) in certs[0].chain.iter().enumerate() {
            assert_eq!(*trust, trusts[i].trust);
        }
    }

    #[test]
    fn test_chain_from_root_to_another_root() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let (kps, trusts) = generate_trust_chain_with_len(&mut trust_graph, 6, HashMap::new());
        let cur_time = current_time();
        let far_future = cur_time + 9999;

        // add first and last trusts as roots
        add_root_peer_id(&mut trust_graph, kps[0].get_peer_id(), 0);
        add_trusts(&mut trust_graph, &trusts, cur_time);
        add_root_with_trust(&mut trust_graph, &kps[5], cur_time, far_future, 0);

        let certs = get_all_certs(&mut trust_graph, kps[5].get_peer_id(), cur_time);
        // first with self-signed last trust, second - without
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0].chain.len(), 6);
        assert_eq!(certs[1].chain.len(), 7);
    }

    #[test]
    fn test_revoke_gc() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let cur_time = 100u64;
        add_root_with_trust(&mut trust_graph, &root_kp, cur_time, cur_time + 999, 4u32);

        let trust_kp = KeyPair::generate_ed25519();
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
            cur_time + 99999,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_ne!(weight, 0u32);

        let revoked_time = cur_time + 1;
        revoke(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            revoked_time,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), revoked_time);
        assert_eq!(weight, 0u32);

        // add trust issued earlier than last revoke
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            revoked_time - 10,
            cur_time + 99999,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), revoked_time);
        assert_eq!(weight, 0u32);
    }

    #[test]
    fn test_update_trust() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let mut cur_time = 100u64;
        add_root_with_trust(&mut trust_graph, &root_kp, cur_time, cur_time + 999, 4u32);

        let trust_kp = KeyPair::generate_ed25519();
        let expires_at_sec = cur_time + 10;
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
            expires_at_sec,
        );

        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), cur_time);
        assert_ne!(weight, 0u32);

        cur_time = expires_at_sec - 1;
        let future_time = expires_at_sec + 10;
        // add trust that expires lately
        add_trust(
            &mut trust_graph,
            &root_kp,
            &trust_kp.get_peer_id(),
            cur_time,
            future_time + 99999,
        );

        // first trust should be replaced by second (and has already been expired)
        let weight = get_weight(&mut trust_graph, trust_kp.get_peer_id(), future_time);
        assert_ne!(weight, 0u32);
    }

    #[test]
    fn path_from_root_to_root_weight() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root1_kp = KeyPair::generate_ed25519();
        let root2_kp = KeyPair::generate_ed25519();
        let cur_time = 100;
        let far_future = cur_time + 99999;
        // root with bigger weight (smaller weight factor)
        add_root_with_trust(&mut trust_graph, &root1_kp, cur_time, far_future, 0u32);
        // opposite
        add_root_with_trust(&mut trust_graph, &root2_kp, cur_time, far_future, 5u32);

        // issue trust from root2 to any other peer_id
        let issued_by_root2_peer_id = KeyPair::generate_ed25519().get_peer_id();
        add_trust(
            &mut trust_graph,
            &root2_kp,
            &issued_by_root2_peer_id,
            cur_time,
            far_future,
        );

        let root2_weight_before = get_weight(&mut trust_graph, root2_kp.get_peer_id(), cur_time);
        let issued_by_root2_peer_id_before =
            get_weight(&mut trust_graph, issued_by_root2_peer_id, cur_time);
        // issue trust from root1 to root2
        add_trust(
            &mut trust_graph,
            &root1_kp,
            &root2_kp.get_peer_id(),
            cur_time,
            far_future,
        );

        let root2_weight_after = get_weight(&mut trust_graph, root2_kp.get_peer_id(), cur_time);
        let issued_by_root2_peer_id_after =
            get_weight(&mut trust_graph, issued_by_root2_peer_id, cur_time);

        assert!(issued_by_root2_peer_id_before < issued_by_root2_peer_id_after);
        assert!(root2_weight_before < root2_weight_after);
    }

    #[test]
    fn add_self_signed_weight() {
        let mut trust_graph = marine_test_env::trust_graph::ServiceInterface::new();
        clear_env();

        let root_kp = KeyPair::generate_ed25519();
        let cur_time = 100;
        let far_future = cur_time + 99999;

        add_root_with_trust(&mut trust_graph, &root_kp, cur_time, far_future, 0u32);

        // issue trust from root to any other peer
        let other_peer_kp = KeyPair::generate_ed25519();
        add_trust(
            &mut trust_graph,
            &root_kp,
            &other_peer_kp.get_peer_id(),
            cur_time,
            far_future,
        );

        let weight_before = get_weight(&mut trust_graph, other_peer_kp.get_peer_id(), cur_time);

        // issue self-signed trust
        add_trust(
            &mut trust_graph,
            &other_peer_kp,
            &other_peer_kp.get_peer_id(),
            cur_time,
            far_future,
        );

        let weight_after = get_weight(&mut trust_graph, other_peer_kp.get_peer_id(), cur_time);
        assert_eq!(weight_after, weight_before);
    }

    #[test]
    fn test_get_one_host_cert() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let (key_pairs, trusts) =
            generate_trust_chain_with_len(&mut trust_graph, 5, HashMap::new());

        let cur_time = current_time();
        let root_peer_id = key_pairs[0].get_peer_id();
        add_root_peer_id(&mut trust_graph, root_peer_id, 1);

        for auth in trusts.iter() {
            add_trust_checked(&mut trust_graph, auth.trust.clone(), auth.issuer, cur_time);
        }

        let cp = get_correct_timestamp_cp_with_host_id(
            0,
            key_pairs.last().unwrap().get_peer_id().to_base58(),
        );
        let certs = trust_graph.get_host_certs_cp(cur_time, cp);

        assert!(certs.success, "{}", certs.error);
        let certs = certs.certificates;
        assert_eq!(certs.len(), 1);

        for (i, trust) in certs[0].chain.iter().enumerate() {
            assert_eq!(*trust, trusts[i].trust);
        }
    }

    #[test]
    fn test_get_one_host_cert_from() {
        let mut trust_graph = ServiceInterface::new();
        clear_env();
        let (key_pairs, trusts) =
            generate_trust_chain_with_len(&mut trust_graph, 5, HashMap::new());

        let cur_time = current_time();
        let root_peer_id = key_pairs[0].get_peer_id();
        add_root_peer_id(&mut trust_graph, root_peer_id, 1);

        for auth in trusts.iter() {
            add_trust_checked(&mut trust_graph, auth.trust.clone(), auth.issuer, cur_time);
        }

        let cp = get_correct_timestamp_cp_with_host_id(
            1,
            key_pairs.last().unwrap().get_peer_id().to_base58(),
        );
        let certs = trust_graph.get_host_certs_from_cp(
            key_pairs[3].get_peer_id().to_base58(),
            cur_time,
            cp,
        );

        assert!(certs.success, "{}", certs.error);
        let certs = certs.certificates;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].chain.len(), 5);

        for (i, trust) in certs[0].chain.iter().enumerate() {
            assert_eq!(*trust, trusts[i].trust);
        }
    }
}
