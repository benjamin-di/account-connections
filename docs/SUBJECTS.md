# Resolve verified subjects

`account_connections.subjects.Subjects` maps an exact, verified issuer/subject
pair to an application person. Display names, email and editable claims do not
select a person. Hosts verify browser identities and trusted MCP identities and
check application eligibility before resolving them. The library performs no
identity verification or provider credential acquisition.

## Enable an installation

Construct `Subjects(people)` for the same `People` authority used by the
application. Call `initialize(bindings, retained_credentials=...)` once during
installation or an explicit migration. `bindings` contains `(Identity, person)`
pairs for every retained person, including departures. Inspect the application's
provider, initialization, budget and control state independently; the library
cannot discover these external stores. Empty bindings are accepted only when
canonical authority is empty and `retained_credentials=False`.

Existing person identifiers and records remain unchanged. Previously unbound
aliases require independent, exact owner evidence in the migration; names and
provider cookies are insufficient. Duplicate identities, duplicate person
identifiers, mismatched bindings, incomplete controls and unmapped retained
people refuse initialization. A completed index cannot be replaced by another
migration. An interrupted initialization can finish only its identical plan.

The index and its initialization marker are private authority. Back up and
restore them consistently with canonical records. Ordinary requests never
rebuild a missing or corrupt index. Index rollback or destructive restoration
requires an explicit recovery plan; do not regenerate it from current logins.
Applications that have not enabled `Subjects` retain their existing interfaces.

## Resolve each caller

Call `resolve(identity, namespaces=..., retained_credentials=census)` and then
`People.contact` with the same verified identity and current admission evidence.
Both browser and trusted MCP paths must do this before protected work. The
resolver returns a person identifier; it does not grant access. Re-admission
still requires the existing explicit, successful browser callback contract;
ordinary positive directory responses cannot clear departure or forgotten state.

Use `Subjects.lookup(identity)` when allocation is inappropriate, including a
verified lost-group callback or an ordinary browser session. It returns only a
completed existing binding; unknown and pending identities return `None` without
creating records. Missing or conflicting marked authority refuses. A host may
disable that known person after a verified negative admission result, without
enrolling the denied identity or changing anyone else's control state.

`census(person)` checks only local retained provider/initialization state for the
exact proposed person and returns a boolean. It runs under the authority lock
before new or pending enrollment; it must perform no network or browser work.
Existing resolved owners do not invoke this callback. Never pass a callback that
ignores an existing credential, provider generation or initialization watermark.

New person identifiers contain 32 lowercase letters/digits and include both
issuer and subject in their hash. A collision refuses enrollment. Each fresh
person starts disconnected, with no shares and no selected account. Existing
namespace controls, credentials, selections, grants and budgets remain in place.
Namespace additions require the existing explicit namespace migration contract.

New allocations persist a pending identity before canonical publication. A retry
may complete the same empty allocation. Lost marked controls, changed pending
controls, provider state or unavailable authority refuse instead of creating a
replacement account. Ordinary lookups read the selected person's controls;
another person's damaged controls do not block an existing healthy person.

## Integrate and recover

Migrate all entrypoints together: browser callback, ordinary browser request,
trusted MCP caller, refused-group callback and keeper/maintenance role. Preserve
standalone owner constraints and do not fall back to a configured default when
headers are absent or invalid. Applications own repeated-header rejection,
issuer pinning, backend authentication and current membership checks.

The new index is optional until every entrypoint uses it. Before activation,
qualify the installed package, two fresh users, retained accounts, provider-state
continuity, concurrent/crashed first contact, departure and lost controls.
Rollback must retain the current index and controls. Returning to alias-only
entrypoints needs an explicit route/configuration rollback; it must not move
credentials into another person's account or discard newer authority.
