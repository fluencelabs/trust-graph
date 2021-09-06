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

// TODO: clear DB before every test, run in 1 thread
#[cfg(test)]
mod tests {
    use fluence_keypair;
    use fluence_keypair::KeyPair;
    use marine_rs_sdk_test::marine_test;
    use std::time::Duration;

    macro_rules! issue_trust {
        ($trust_graph:expr, $issuer_kp:expr, $issued_peer_id: expr, $expires_at:expr, $issued_at: expr) => {{
            let trust_metadata_result = $trust_graph.get_trust_metadata(
                $issued_peer_id.to_base58(),
                $expires_at,
                $issued_at,
            );
            assert_result!(trust_metadata_result);

            let metadata = trust_metadata_result.result;
            let signed_metadata = $issuer_kp.sign(&metadata).unwrap().to_vec().to_vec();
            let trust_result = $trust_graph.issue_trust(
                $issued_peer_id.to_base58(),
                $expires_at,
                $issued_at,
                signed_metadata.to_vec(),
            );
            assert_result!(trust_result);

            trust_result.trust
        }};
    }

    macro_rules! assert_result {
        ($result:expr) => {{
            assert!($result.success, "{:?}", $result.error);
        }};
    }

    #[marine_test(config_path = "../Config.toml", modules_dir = "../artifacts/")]
    fn issue_trust_test() {
        let issuer_kp = KeyPair::generate_ed25519();
        let issued_peer_id = KeyPair::generate_ed25519().get_peer_id();
        let issued_at = 0u64;
        let expires_at = 10u64;
        let trust = issue_trust!(
            trust_graph,
            issuer_kp,
            issued_peer_id,
            expires_at,
            issued_at
        );
        let verify_result = trust_graph.verify_trust(trust, issuer_kp.get_peer_id().to_base58(), 0);
        assert_result!(verify_result);
    }

    #[marine_test(config_path = "../Config.toml", modules_dir = "../artifacts/")]
    fn issue_cert_test() {
        let issuer_kp = KeyPair::generate_ed25519();
        let issued_peer_id = KeyPair::generate_ed25519().get_peer_id();
        let issued_at = 0u64;
        let expires_at = 10u64;
        let root_trust = issue_trust!(
            trust_graph,
            issuer_kp,
            issuer_kp.get_peer_id(),
            expires_at,
            issued_at
        );
        let trust = issue_trust!(
            trust_graph,
            issuer_kp,
            issued_peer_id,
            expires_at,
            issued_at
        );

        let cert_result = trust_graph.issue_root_certificate_checked(root_trust, trust, 0u64);
        assert_result!(cert_result);
    }

    #[marine_test(config_path = "../Config.toml", modules_dir = "../artifacts/")]
    fn extend_cert_test() {
        let issuer_kp = KeyPair::generate_ed25519();
        let issued_peer_id = KeyPair::generate_ed25519().get_peer_id();
        let issued_at = 0u64;
        let expires_at = 10u64;
        let root_trust = issue_trust!(
            trust_graph,
            issuer_kp,
            issuer_kp.get_peer_id(),
            expires_at,
            issued_at
        );
        let trust = issue_trust!(
            trust_graph,
            issuer_kp,
            issued_peer_id,
            expires_at,
            issued_at
        );

        let cert_result = trust_graph.issue_root_certificate_checked(root_trust, trust, 0u64);
        assert_result!(cert_result);
        println!("{:?}", cert_result.cert);

        assert_result!(trust_graph.add_root(issuer_kp.get_peer_id().to_base58(), 300));

        let insert_res = trust_graph.insert_cert(cert_result.cert, 0u64);
        assert_result!(insert_res);
        let all_certs_res = trust_graph.get_all_certs(issued_peer_id.to_base58());
        assert_result!(all_certs_res);
        assert_eq!(all_certs_res.certificates.len(), 1);
        println!("{:?}", all_certs_res.certificates);
    }
}
