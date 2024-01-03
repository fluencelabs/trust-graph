# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.1 to 0.4.2
    * fluence-keypair bumped from 0.10.0 to 0.10.1

## [0.4.9](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.8...trust-graph-wasm-v0.4.9) (2023-12-28)


### Bug Fixes

* **deps:** update sqlite wasm ([#135](https://github.com/fluencelabs/trust-graph/issues/135)) ([c59451d](https://github.com/fluencelabs/trust-graph/commit/c59451de04ba79152fa8d600a7b456ab24766dd0))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.8 to 0.4.9

## [0.4.8](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.7...trust-graph-wasm-v0.4.8) (2023-12-20)


### Features

* update marine sdk's, configs and sqlite connector ([#129](https://github.com/fluencelabs/trust-graph/issues/129)) ([0b66f4e](https://github.com/fluencelabs/trust-graph/commit/0b66f4e0536633879de46f69ac8391c72ece7e77))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.7 to 0.4.8
    * fluence-keypair bumped from 0.10.3 to 0.10.4

## [0.4.7](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.6...trust-graph-wasm-v0.4.7) (2023-07-04)


### Bug Fixes

* **deps:** update rust crate marine-rs-sdk-test to 0.10.0 ([#106](https://github.com/fluencelabs/trust-graph/issues/106)) ([725d3f8](https://github.com/fluencelabs/trust-graph/commit/725d3f8f48b3bf1ed8605e9ba2da5c966a145f0d))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.6 to 0.4.7
    * fluence-keypair bumped from 0.10.2 to 0.10.3

## [0.4.6](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.5...trust-graph-wasm-v0.4.6) (2023-06-30)


### Reverts

* release master ([#110](https://github.com/fluencelabs/trust-graph/issues/110)) ([d80a43b](https://github.com/fluencelabs/trust-graph/commit/d80a43bcff721aff8fadf3d2d5c252804ce27a6c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.5 to 0.4.6
    * fluence-keypair bumped from 0.10.1 to 0.10.2

## [0.4.5](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.4...trust-graph-wasm-v0.4.5) (2023-05-09)


### Miscellaneous Chores

* **trust-graph-wasm:** Synchronize trust-graph, wasm and api versions


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.4 to 0.4.5

## [0.4.4](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.3...trust-graph-wasm-v0.4.4) (2023-05-09)


### Miscellaneous Chores

* **trust-graph-wasm:** Synchronize trust-graph, wasm and api versions


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.3 to 0.4.4

## [0.4.3](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.2...trust-graph-wasm-v0.4.3) (2023-05-08)


### Miscellaneous Chores

* **trust-graph-wasm:** Synchronize trust-graph, wasm and api versions


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.2 to 0.4.3

## [0.4.1](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.4.0...trust-graph-wasm-v0.4.1) (2023-04-13)


### Bug Fixes

* **deps:** Add trust-graph to workspace and bump sqlite-wasm version ([#87](https://github.com/fluencelabs/trust-graph/issues/87)) ([da38a41](https://github.com/fluencelabs/trust-graph/commit/da38a41ba727a14774a71bba6612b1bf1f498db9))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.4.0 to 0.4.1

## [0.4.0](https://github.com/fluencelabs/trust-graph/compare/trust-graph-wasm-v0.3.2...trust-graph-wasm-v0.4.0) (2023-03-15)


### ⚠ BREAKING CHANGES

* **deps:** update libp2p to 0.39.1 and other deps ([#77](https://github.com/fluencelabs/trust-graph/issues/77))

### Features

* **deps:** update libp2p to 0.39.1 and other deps ([#77](https://github.com/fluencelabs/trust-graph/issues/77)) ([080503d](https://github.com/fluencelabs/trust-graph/commit/080503dcfa2ecf8d09167ff9fe7f750fadf49035))
* **keypair:** add KeyPair::from_secret_key ([#50](https://github.com/fluencelabs/trust-graph/issues/50)) ([a6ce8d9](https://github.com/fluencelabs/trust-graph/commit/a6ce8d9eee20e1ea24eb27c38ac6df6d878292ae))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * trust-graph bumped from 0.3.0 to 0.4.0
    * fluence-keypair bumped from 0.9.0 to 0.10.0

## [Unreleased]

## [0.3.1] - 2022-10-06

### Added
- *(keypair)* add KeyPair::from_secret_key (#50)

### Fixed
- fix bug get_all_certs_from, update example (#44)
- fix db paths (#28)

### Other
- set version of fluence-keypair to 0.8.0
- fluence-keypair 0.8.0
- libp2p-core 0.33.0 (#49)
- remove circle, update gh, add lints; remove warnings (#43)
- Add memory leak temporary mitigation (#42)
- High-level Aqua API (#35)
- fluence-keypair 0.6.0
- libp2p-core 0.31.0 (from crates.io) (#37)
- Fix revocations logic (#34)
- Remove mutex from TG instance (#31)
- refactoring (#30)
- Trust Graph: implement WASM built-in (#18)
