# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [0.1.1] - 2026-10-31

_No changes to the published package._

### Upgrade

- Action required: none.
- Rollback: no application state changes from 0.1.0.

## [0.1.0] - 2026-10-31

### Added

- Add explicit offers, owned/shared selection, capability checks, revocation and leave transitions (#1)
- Add escaped native forms and selected-connection controls (#1)
- Document host identity, transaction, lifecycle and saved-content boundaries (#1)

### Upgrade

- Action required: applications must supply identity, eligibility, native storage transactions and credential barriers.
- Rollback: initial release; remove only before adopting application sharing state.

[0.1.0]: https://github.com/benjamin-di/account-connections/releases/tag/v0.1.0

[0.1.1]: https://github.com/benjamin-di/account-connections/releases/tag/v0.1.1
