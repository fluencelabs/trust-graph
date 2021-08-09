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
mod tests {
    use marine_rs_sdk_test::marine_test;
    use fluence_identity;
    use std::time::Duration;

    #[marine_test(config_path = "../Config.toml", modules_dir = "../artifacts/")]
    fn test() {

        let root_kp = Keypai
        let root_kp2 = KeyPair::generate();
        let second_kp = KeyPair::generate();

        let expires_at = Duration::new(15, 15);
        let issued_at = Duration::new(5, 5);

        let cert = trust_graph::Certificate::issue_root(
            &root_kp,
            second_kp.public_key(),
            expires_at,
            issued_at,
        );
        trast_graph.add_root(root_kp.public().into(), 0).unwrap();
        tg.add_root_weight(root_kp2.public().into(), 1).unwrap();
        tg.add(cert, Duration::new(10, 10)).unwrap();

        let a = tg.get(second_kp.public_key()).unwrap();
        let str = format!("{:?}", a);
        log::info!("{}", &str);
    }
}