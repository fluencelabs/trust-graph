# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.2](https://github.com/fluencelabs/trust-graph/compare/keypair-v0.10.1...keypair-v0.10.2) (2023-06-30)


### Features

* update libp2p identity  ([#109](https://github.com/fluencelabs/trust-graph/issues/109)) ([d04120b](https://github.com/fluencelabs/trust-graph/commit/d04120bacf802a7e1127f4955b7391b0a4353128))


### Bug Fixes

* **keypair:** update description ([#105](https://github.com/fluencelabs/trust-graph/issues/105)) ([f7ef0f8](https://github.com/fluencelabs/trust-graph/commit/f7ef0f8da095fe1fef80faaa0b0c2d5ef854bd16))


### Reverts

* release master ([#110](https://github.com/fluencelabs/trust-graph/issues/110)) ([d80a43b](https://github.com/fluencelabs/trust-graph/commit/d80a43bcff721aff8fadf3d2d5c252804ce27a6c))

## [0.10.1](https://github.com/fluencelabs/trust-graph/compare/keypair-v0.10.0...keypair-v0.10.1) (2023-05-02)


### Features

* **keypair:** Make `KeyFormat` more convenient ([#91](https://github.com/fluencelabs/trust-graph/issues/91)) ([9b942ea](https://github.com/fluencelabs/trust-graph/commit/9b942eacca49d0468b4d7512667102363a6c9aa3))

## [0.10.0](https://github.com/fluencelabs/trust-graph/compare/keypair-v0.9.0...keypair-v0.10.0) (2023-03-15)


### ⚠ BREAKING CHANGES

* **deps:** update libp2p to 0.39.1 and other deps ([#77](https://github.com/fluencelabs/trust-graph/issues/77))

### Features

* **deps:** update libp2p to 0.39.1 and other deps ([#77](https://github.com/fluencelabs/trust-graph/issues/77)) ([080503d](https://github.com/fluencelabs/trust-graph/commit/080503dcfa2ecf8d09167ff9fe7f750fadf49035))
* **keypair:** add KeyPair::from_secret_key ([#50](https://github.com/fluencelabs/trust-graph/issues/50)) ([a6ce8d9](https://github.com/fluencelabs/trust-graph/commit/a6ce8d9eee20e1ea24eb27c38ac6df6d878292ae))

## [Unreleased]

## [0.8.1] - 2022-10-06

### Added
- *(keypair)* add KeyPair::from_secret_key (#50)

### Other
- set version of fluence-keypair to 0.8.0
- fluence-keypair 0.8.0
- libp2p-core 0.33.0 (#49)
- remove circle, update gh, add lints; remove warnings (#43)
- fluence-keypair 0.6.0
- libp2p-core 0.31.0 (from crates.io) (#37)
- Remove serde version lock (#15)
- Fix revocations logic (#34)
- Trust Graph: implement WASM built-in (#18)
- Move fluence-identity to fluence-keypair (#17)
