# Application adapter contract

The `1.0.0` interface is stable. Run conformance against an application's
real setup before adopting its integration. All examples use synthetic identities.

## Setup and authority

```python
from pathlib import Path
from account_connections.people import Identity, People, Policy
from account_connections.controls import Controls
from account_connections.admission import AdmissionService

people = People(Path("state/connection-authority"), max_shares=20)
controls = Controls(people)
policy = Policy("1", frozenset({"cart", "orders", "payments"}))
# Load a dedicated application key from private persistent configuration.
admission = AdmissionService(people, controls, b"synthetic-example-key" * 2)
people.contact("alice", namespaces=["example"], retained_credentials=False)
# After a verified browser identity performs its first explicit action:
people.contact(
    "alice",
    namespaces=["example"],
    identity=Identity("https://identity.example.com", "subject-alice"),
    label="Alice",
    explicit=True,
)
```

The root and its control files must be owned and private (0700/0600), and storage
is POSIX. Each person has a v3 record with an immutable issuer/subject binding,
display name and namespace rows containing controls, selection and grants.
Canonical authority requires POSIX locks, ownership/mode enforcement, no-follow file
opens and directory `fsync`; v1 makes no Windows storage/lock compatibility claim.
Portable applications must keep an explicit platform/mode import boundary and
retain their native authority for unsupported modes. A native default/custodian
ledger is an explicit migration exception until equivalent portability and the
provider's atomic publication journal are supported; do not report it deleted.
People identifiers and namespace identifiers are bounded local keys. Names are
display-only. The host maps verified identity to a person and checks current
membership before every call, including all workload calls and browser callbacks.
An external caller never supplies the actor or owner used for tool routing.

Call `contact(person, namespaces=...)` on the first admitted browser or MCP
contact; no application user registry supplies the roster. The host admits the
signed identity's required group and admin-owned person claim before this call.
Browser contact passes `Identity(issuer, subject)` and its verified `label`;
header-only MCP contact passes no identity and cannot pin a subject. Only an
explicit browser action sets `explicit=True` to pin that immutable identity.
Contact never selects an account, connects credentials or grants shared access.
`enroll` and `bind` remain lower-level APIs for explicit migration/operator use.

Before enrolling a new person, the application checks
its credential paths and passes `retained_credentials=True` if any retained
credentials exist. Enrollment then refuses. An initialization marker also stops
recreation after a canonical file is lost. Reads never initialize or repair.
Adding namespaces to an existing record requires an explicit reviewed migration.
Unreadable records stop only that person; `offers` reports unavailable owners
without hiding healthy owners. Limits are 100 people/namespaces/recipients; set
`max_shares` to the application's smaller provider policy when required.

## People, labels and departures

`roster()` returns frozen `Person(id, label, active, available)` rows for enrolled
people plus existing grant recipients. A missing or unreadable recipient stays
visible with `available=False`, so its grants remain revocable. Labels use the
record's display-only `name`, falling back to the ID; collisions ignoring case
append ` (ID)` to each label. `label(person)` supplies the same rendering.
Signed browser contact stores the current verified label (including clearing an
absent label); header-only contact preserves it. Labels strip control characters,
normalize whitespace and stop at 80 characters. They never confer admission or
match provider accounts. Use `signin-window`'s `identity["label"]`, whose claim
precedence is configured display name, then real name, then no label.

`set_inactive(person, identity)` marks an existing person after a verified
sign-in loses the app group. The identity must match any pinned subject. All
new admission, offers, choices, connection attempts and final publication refuse
the durable marker. Existing grants remain revocable. An ordinary browser cookie
or MCP contact cannot clear it, even with the same identity. Only a **newly
verified successful OIDC callback** may call `contact(..., identity=identity,
readmit=True)`. Never pass `readmit` on ordinary page/tool requests; old browser
sessions may retain an admitted group after a later refused sign-in.

`forget(person)` is an operator action: it writes an irreversible forgotten
tombstone before clearing the person's grants, selection and connection epochs,
incoming grants and other people's selections of that person. It returns IDs of
damaged records whose reference cleanup could not be completed, without repairing
them. The tombstone still denies that person throughout interrupted cleanup.
The application owns credential disposal. Ordinary contact, directory refresh and
new browser sign-in can never reactivate a forgotten person. Preserve inactivity
and forgotten markers with the authority during backup/recovery.

An optional `People(..., directory=lookup)` accepts a callable
`Identity -> DirectoryPerson(admitted: bool, label: str | None) | None`.
The hook performs **exact-subject** lookup only; the library never lists/searches
the identity provider. `None` denies; hook errors become `directory_unavailable`.
`refresh(person)` checks an existing pinned identity and caches a negative verdict
as inactivity or updates its label. Positive refresh never reactivates inactivity.
Contact checks the directory before enrollment; header-only first contact without
a pinned identity needs browser sign-in when this hook is configured.
Lookup runs outside the authority transaction and rechecks the binding before
writing. `require_admitted(person)` checks only durable local state and is safe
inside the transaction. Before a call captures authority, refresh both its actor
and selected owner outside the lock, then recheck their local admission inside.
Roster returns local state: refresh available entries outside the lock before
rendering; isolate individual directory failures and hide their share/choose
actions for that request. A failed refresh is not a positive cached admission.
Before share/choose mutations, likewise refresh their recipient/selected owner
outside the transaction before the local fenced operation.

`people.store.lock()` is the shared, reentrant, process-safe authority lock. All
public mutators take it themselves. A cross-record action can wrap several calls
in it. It precedes final record writes, and must not surround provider/browser
I/O. Credential operation locks are acquired **before** the authority lock. A
disconnect writes its barrier under authority, releases it, then drains operation
locks. Never wait for an operation lock while holding authority.

## Connection lifecycle

```python
attempt = controls.begin("alice", "example", ttl=1200)
# Acquire and independently verify a session using provider-specific code.
controls.stage("alice", "example", attempt, lambda: None)  # app stages bytes
epoch = controls.publish("alice", "example", attempt, lambda: None)  # app publishes bytes
```

`stage` and `publish` callbacks write application-owned credentials in their own
format; the library never receives or persists credential bytes. Stage retains
only a completion flag and expiry. Final publication holds the operation and
authority locks, checks the exact current attempt, and commits a blocked epoch
before calling the writer. A crash during credential replacement remains stopped.
The writer must perform only the final bounded atomic filesystem publication;
verification, network calls and browser work happen beforehand. The optional
`generation` argument must exceed the retained watermark. Without it the library
increments its watermark. `require_staged=False` is for already-verified native
publication that has no separate staging phase, not a verification exemption.

`begin(owner, ns, ttl=...)` creates a fresh revision and a bounded human lease.
`current(owner, ns, revision)` checks the attempt and its expiry.
`started(owner, ns, revision, ttl=...)` extends a current attempt.
`pending(owner, ns)` returns staged metadata, never credentials.
`cancel(owner, ns, expected)` invalidates an attempt; stale cancellation is a no-op.
`status` returns a detached validated snapshot. `require_active(..., epoch=...)`
checks the disconnect barrier and optional captured epoch.
`require_maintenance` also refuses a human lease. `maintain(owner, ns, epoch,
writer)` fences a provider's final cookie refresh against both conditions.

Only the owner's verified management action may call these mutators. A successful
provider sign-in does not prove stable account identity: applications enforce
their own provider binding, duplicate-account policy and independent verification.
Window concurrency and installation caps remain provider policy.

`disconnect(owner, ns, delete, expected=revision, cancel=callback, timeout=10)`
first commits a new `disconnecting` epoch, then cancels the browser, drains
admitted work, deletes credentials and commits `disconnected`. A stale form is a
no-op. If cancel/delete/drain fails, the barrier survives a restart. Resume with
`finish_disconnect(owner, ns, barrier_revision, delete, timeout=10)`. The explicit
`suspend` method supplies that revision when cleanup must be scheduled separately.

## Sharing and call admission

`offer(owner, ns, recipient, policy=..., capabilities=frozenset(...),
expected=old_grant_revision_or_None)` creates or updates an offer. A policy/scope
change creates a fresh grant revision. It never changes the recipient's selection.
`select(actor, ns, owner, policy=..., expected=selection_revision,
grant_revision=offered_revision_or_None)` explicitly accepts the offer.
`revoke(owner, ns, recipient, expected=grant_revision)` commits denial immediately.
`leave(actor, ns, owner, expected=grant_revision)` revokes before clearing selection.
There is no fallback. Reissuing a grant cannot revive the old selection. Owner
selection has no grant. The host must enforce owner-only use of owner APIs; sharing
never makes a recipient an owner, manager or transitive sharer.

```python
captured = admission.capture("alice", "example", policy=policy, capability="cart")
context = admission.token(captured)
with controls.admitted(captured.owner, captured.namespace, epoch=captured.epoch):
    pass  # use only this owner's cached client/session throughout this call
# Shared writes require a token from the most recent read:
admission.capture(
    "alice", "example", policy=policy, capability="cart", context=context, require_context=True
)
```

Capture before any protected provider **or cache** access. The immutable result
contains actor, owner, namespace, selection/grant revisions, policy version,
capabilities, epoch and control revision. Its HMAC token is scoped to all of them.
`shared_context_only=False` requires a context for owned writes as well.
`revalidate(captured, policy=...)` is for continuations; a changed authority refuses
instead of resolving another account. Already-admitted work may finish on its
captured account after revoke; subsequent captures fail. Disconnect stops new
borrows immediately and drains existing borrows before deleting credentials.
Keep the borrow inside upstream worker-thread execution when that worker owns I/O;
do not acquire it on a thread and release it before that worker finishes.

Closed rule errors retain their original `ConnectionError.code`. Persistence and
lifecycle failures use `StateError.code`, including `owner_reconnect`,
`connection_disconnected`, `account_changed`, `connection_busy` and
`identity_mismatch`. Applications preserve their existing public error vocabulary.
No exception text or provider response belongs in tool errors.

## Optional web routes

`web.routes(people, auth, hooks, origin="https://app.example.com",
prefix="/connections", mount_path="", identity=None)` returns Starlette routes. `auth` is signin-window 0.7
`BrowserAuth` (or a compatible implementation). Keep its OIDC login/callback routes.
`Hooks` supplies `actor(identity)`, `namespaces(person)`, `policy(namespace)`,
optional `actions={"connect": async_handler, ...}`, optional
`render_namespace(person, namespace)`, `render_namespace_status(person, namespace)`,
`capability_labels(namespace)` and `default_capabilities(namespace)`.

The generic page provides own/shared account selection, offers, revoke and leave.
Default share capabilities are empty unless the application declares defaults.
Offered and valid selected grants show granted permissions and declared permissions
not shared. Empty grants explicitly show none. `capability_labels(namespace)`
optionally maps canonical capability IDs to display labels, with ID fallback;
labels are escaped in summaries and owner checkboxes. Labels never change grants,
submitted capability IDs or admission policy.

Home checks freshness through `auth.require_fresh` outside authority transactions.
A stale GET keeps safe connection/permission status and puts an escaped
`auth.step_up_url` confirmation link before it, without any generic mutation forms.
`render_namespace` supplies trusted provider action markup and is invoked only
with fresh authentication. `render_namespace_status` optionally supplies read-only
provider status for both fresh and stale GETs; it must not emit mutation forms.
Both hooks run outside authority transactions, must escape their data and perform
no provider/network work. Existing adapters with mixed status/actions can move
read-only markup to the status hook; do not filter HTML or add host auth wrappers.
POST freshness validation remains independent and unchanged.

Pass the host application's installed build as a
`signin_window.connections.PageIdentity` in `identity`. The router forwards this
object unchanged to the shared renderer on its home, unavailable-controls and
form-failure pages. The footer identifies the host, never this library. Supply
the same identity to the host's authentication and provider pages separately.
This option requires a renderer release exposing `PageIdentity` and the
`page(..., identity=...)` argument; unsupported renderers refuse route creation
when identity is supplied. Existing callers can omit identity with their current
renderer, but that does not establish footer adoption. No Git or environment
lookup occurs in these routes.
`Hooks.enroll(person)` lets the provider refuse lost credentials/authority using
its external initialization watermark before generic first contact. The router
then calls `People.contact` using only verified browser identity and label.
`Hooks.connection_ready(owner, namespace)` reads local provider session status
without network work. It runs outside authority transactions. Sharing requires
both an active ledger and a literal `True` result; false, exceptions and other
return values are unavailable. The share POST rechecks both.
Absent/expired sessions show the disconnected empty state even with an active
ledger. Omit this hook only if active control already implies local readiness.
It cannot establish that a provider will accept the session on the next request.
This hook affects management availability, not protected-call admission or public
guest routing. Route an explicitly public call before capture only under the
application's public-call policy. A rejected shared selection must never become
a guest or owned-account fallback; charge the caller's budget before credential
access and isolate guest sessions from retained provider credentials.
`provider_namespace_field` defaults to `namespace`; set it to an application's
existing field (for example `site`) to preserve provider form contracts. Generic
sharing forms always use `namespace`. Provider hooks receive their original fields
and own revision checks so stale cancellation can retain the application's no-op
behavior. Unknown or malformed namespaces return 400 before invoking a hook.
It and action handlers run outside authority transactions. Other hooks supply
pure verified mapping/configuration, not provider I/O. Provider forms submit
`namespace` and `control_revision`; old field aliases can be included too.
Handlers receive `(request, authenticated_person, namespace, form)` and must
recheck their supplied revision at the actual credential publication or deletion.

Every POST checks a verified browser identity, its pinned binding, exactly one
matching Origin and `auth.require_fresh`; stale authentication returns its
confirmation page unchanged. It never redirects a submitted form into OIDC.
`auth.step_up_url` supplies navigation links; `auth.refused` explains admission
failures. GETs may enroll first contact and update display labels, but never
choose accounts, change grants or publish credentials. The library escapes generic display data,
bounds form parsing and sets restrictive CSP/no-store headers. Applications can
choose compatible route prefixes and provider actions while retaining tool names.
For an app mounted under `/example`, pass `mount_path="/example"` (normally
`auth.prefix`): route matching remains `/connections/`, while forms, navigation
and step-up destinations use `/example/connections/`.

## One-way migration

Use `migrations.hktvmall(people, person, native, policy=...)`,
`migrations.amazon(people, owner, native_controls, identity=..., metadata=...)`, or
`migrations.newsclip(people, person, native_access, native_controls, policy=...,
identity=...)`. Inputs are validated native control/access dictionaries, loaded by
the application's existing private-state reader. They never contain cookies,
browser profiles, keeper credentials, budgets, archives or caches. Applications
preserve those paths and map the existing configured owner explicitly.
For Amazon, pass per-namespace routing `metadata` with exactly `jar_path`,
`keeper_path` and `default_site` string fields. These non-secret paths and
preference enter the snapshot digest and canonical record before the completed
receipt. Do not attach provider routing in a later transaction: interruption
must never expose complete authority with missing credential/budget mappings.

Stop old readers/writers and keep their native authority lock throughout migration.
The library also holds its destination lock. It saves a private immutable source
snapshot, writes a stopped migration receipt, atomically publishes the v3 record,
then commits a completed receipt. Each write is fsynced, including its directory.
During interruption, canonical runtime reads stay stopped. Repeating with the same
native source resumes; a changed source or existing unrelated destination refuses.
A completed migration never repairs a lost record or overwrites subsequent v3
mutations. The native helper snapshots and receipts must be backed up with v3
authority and credentials. Control phases, identities, grant/selection revisions,
scope flags and generation watermarks are preserved. Old in-flight windows must
restart; their callbacks lack a canonical staged attempt and cannot publish.

Rollback to an application that enforces the old controls is incompatible after
migration. Use a fix-forward release while preserving the v3 barriers. Never
restore credentials independently of their current controls or drop initialization
markers. Operator recovery needs separately reviewed evidence, not reader repair.

## Conformance

`account_connections.testing.ConnectionConformance` is a pytest mixin. Supply a
`connection_factory` fixture returning a callable `Path -> Harness`, and return
your application's actual configured `People`, `Controls`, `AdmissionService`,
`Policy`, namespace and a restart factory. See `tests/test_conformance.py` for the
complete executable example. Keep provider-specific characterization tests too:
conformance cannot prove client routing, provider entitlement or keeper budgets.

Checks cover first-contact enrollment without implicit choice or subject binding,
label fallback/collisions, removed-group refusal including old browser contact,
stale publication, persistent disconnect, revoke/leave without
fallback, lost records, retained credentials, immutable captured work, stale
tokens, reissued grants, corruption isolation and immutable identity binding.
