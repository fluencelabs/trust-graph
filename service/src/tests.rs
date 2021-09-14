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
    use crate::service_impl::{TRUSTED_TIMESTAMP_FUNCTION_NAME, TRUSTED_TIMESTAMP_SERVICE_ID};
    use fluence_keypair;
    use fluence_keypair::KeyPair;
    use marine_rs_sdk_test::{marine_test, CallParameters, SecurityTetraplet};

    pub static HOST_ID: &str = "host_id";

    fn get_correct_timestamp_cp(arg_number: usize) -> CallParameters {
        let mut cp = CallParameters::default();
        cp.host_id = HOST_ID.to_string();

        for _ in 0..arg_number {
            cp.tetraplets.push(vec![]);
        }

        cp.tetraplets.push(vec![SecurityTetraplet {
            peer_pk: HOST_ID.to_string(),
            service_id: TRUSTED_TIMESTAMP_SERVICE_ID.to_string(),
            function_name: TRUSTED_TIMESTAMP_FUNCTION_NAME.to_string(),
            json_path: "".to_string(),
        }]);

        cp
    }

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
        let verify_result = trust_graph.verify_trust_cp(
            trust,
            issuer_kp.get_peer_id().to_base58(),
            0,
            get_correct_timestamp_cp(2),
        );
        assert_result!(verify_result);
    }
}
