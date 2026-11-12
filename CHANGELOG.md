# Changelog

All notable changes are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.2.1] - 2026-11-12

_Version 1.2.0 was not published to PyPI or as a public release; 1.2.1 is the same package and ships 1.2.0's changes._

### Upgrade

- Action required: none.
- Rollback: compatible with 1.2.0.

[1.2.1]: https://github.com/benjamin-di/account-connections/releases/tag/v1.2.1

## [1.2.0] - 2026-11-11

### Added

- Forward an optional host build identity to the shared Connections renderer on home, unavailable-controls and form-failure pages; supplying it requires a renderer with an `identity` argument, and existing callers may omit it (#13)

### Fixed

- Render generic form errors in the same accessible page shell, preserving their HTTP status, response security policy and local login path (#13)

### Upgrade

- Action required: none.
- Rollback: compatible with 1.1.2 for callers that do not pass a build identity; authority records, authentication and account actions are unchanged.

[1.2.0]: https://github.com/benjamin-di/account-connections/releases/tag/v1.2.0

## [1.1.2] - 2026-11-03

### Fixed

- Render generic `/connections/` pages in the common responsive Connections shell, with labeled status cards, clear empty sharing states and consistent signed-in identity text (#10).
- Permit the shared stylesheet and exact fixed script under the restrictive page policy while preserving exact-Origin form checks and read-only step-up states (#10).

### Upgrade

- Action required: none.
- Rollback: compatible with 1.1.1; authority records, authentication and account actions are unchanged.

[1.1.2]: https://github.com/benjamin-di/account-connections/releases/tag/v1.1.2

## [1.1.1] - 2026-11-02

### Fixed

- Preserve the configured Origin on browser form submissions while withholding page referrers from cross-origin destinations. Exact-Origin and fresh-authentication checks remain enforced.

### Upgrade

- Action required: none.
- Rollback: compatible with 1.1.0; authority formats are unchanged, but 1.1.0 retains the browser form-submission defect.

## [1.1.0] - 2026-11-02

### Added

- Add an optional exact-subject HTTPS directory transport with strict issuer and response validation, bounded caller latency and worker capacity, and safe failures without cached admission.
- Separate private authority storage and process locks behind one qualified platform backend; optional module imports no longer load unsupported POSIX primitives.

### Fixed

- Reject ambiguous HTTP body framing and unsupported transfer encodings before interpreting directory admission responses.

### Upgrade

- Action required: none. Directory integration remains opt-in and requires a restricted client policy and independently scoped key. Canonical authority remains POSIX-only; unsupported platforms refuse before creating state.
- Rollback: compatible with 1.0.1 when the optional directory transport is unused; remove that integration before reverting. Authority record formats are unchanged.

## [1.0.1] - 2026-11-02

### Fixed

- Declare the public migration API identifiers and exact synthetic rejected-credential fixture in export checks so the unchanged runtime can be published.

### Upgrade

- Action required: none.
- Rollback: compatible with 1.0.0; application state and runtime behavior are unchanged.

## [1.0.0] - 2026-11-02

### Added

- Add private, namespace-aware people records with pinned immutable identities.
- Enroll admitted people on contact, render distinct display-name labels and retain inactive/forgotten authority with an optional exact-subject directory lookup.
- Add durable connection controls, staged attempts, fenced credential writers and draining disconnects.
- Capture immutable per-call admission and sign account-context tokens bound to current authority.
- Add optional management routes with fresh authentication and exact-Origin protection.
- Gate sharing on local provider readiness and isolate unavailable owners in the management page.
- Display granted and withheld permissions with optional escaped labels; keep stale-session pages read-only with confirmation before mutation controls.
- Add resumable native control migrations with private source snapshots and a reusable conformance suite.
- Preserve the existing pure sharing-rules and form-rendering interfaces.

### Upgrade

- Action required: integrate and qualify the application adapter with its conformance suite before adopting v3 state; install the `web` extra and signin-window 0.7 for management routes, labels and verified sign-in callbacks. Canonical storage and controls require POSIX; portable applications retain native authority in unsupported modes behind an explicit import boundary.
- Rollback: after a native control migration, earlier application versions are incompatible; fix forward while retaining v3 records and snapshots.

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

[1.0.0]: https://github.com/benjamin-di/account-connections/releases/tag/v1.0.0

[1.0.1]: https://github.com/benjamin-di/account-connections/releases/tag/v1.0.1

[1.1.0]: https://github.com/benjamin-di/account-connections/releases/tag/v1.1.0
