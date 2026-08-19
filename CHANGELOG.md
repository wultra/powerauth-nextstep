# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Changed Docker images to be based on the Wultra base image [(#63)](https://github.com/wultra/powerauth-nextstep/issues/63)

### Fixed

- Removed the `javascript` language from the CodeQL analysis workflow, as the repository contains no JS/TS source [(#60)](https://github.com/wultra/powerauth-nextstep/issues/60)

## [2.2.1] - 2026-08-12

### Fixed

- Updated `wultra-core` to 2.2.1 to fix date serialization compatibility with Jackson 3 [(#54)](https://github.com/wultra/powerauth-nextstep/issues/54)

## [2.2.0] - 2026-07-23

### Changed

- Upgraded Docker base image to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25) [(#46)](https://github.com/wultra/powerauth-nextstep/issues/46)
- Migrated to Spring Boot 4 and Jackson 3 [(#37)](https://github.com/wultra/powerauth-nextstep/issues/37)

[unreleased]: https://github.com/wultra/powerauth-nextstep/compare/2.2.1...HEAD
[2.2.1]: https://github.com/wultra/powerauth-nextstep/compare/2.2.0...2.2.1
[2.2.0]: https://github.com/wultra/powerauth-nextstep/compare/2.0.0...2.2.0
