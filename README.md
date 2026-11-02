# account-connections

Python connection ownership, lifecycle, explicit sharing and per-call admission
for authenticated applications. The library stores control records; applications
keep their own credentials, provider clients, budgets and caches.

Owners offer access. Recipients choose in one action and can switch between owned
and shared connections, including after disconnecting their own. Offers never
change routing. Revoke, leave and scope changes never fall back. Reissued grants
have new revisions; an old selection cannot regain access.

## Modules

The original dependency-free `rules` and `ui` interfaces remain available.
Optional `people`, `controls`, `admission`, `migrations` and `testing` modules add
private POSIX control storage and an application conformance suite. Install
`account-connections[web]` for Starlette management routes using signin-window
0.7. The base package does not import web, browser or identity dependencies.

See [the adapter contract](docs/ADAPTERS.md) for the complete integration API,
lock order, migration protocol and executable conformance fixture.

The v1 canonical storage and controls require POSIX. They use process-safe file
locks, private ownership/mode checks, no-follow opens and durable directory writes.
Applications supporting Windows must import these modules only inside an explicit
POSIX mode and retain their portable native authority elsewhere. Replacing file
locks alone does not provide Windows support.

## Host contract

The host authenticates the actor, checks current application membership and selects
the provider namespace. The library validates canonical records. The actor and
owner come from those bindings, never an untrusted tool parameter. Only owners
may acquire credentials, disconnect or offer access. Recipients cannot reshare.

`People` serializes grant and selection transitions and persists them before
success. The pure `rules` functions still require the application's transaction.
Do not hold an authority lock across network/browser work. Capture immutable
admission before protected I/O or cache access, then borrow credentials through
`Controls.admitted`. Publication uses the final fenced `Controls.publish`
callback. Admission never overrides provider generations, holds, budgets or leases.

Revoke durably before clearing a departing selection, holding the transaction
lock throughout. A crash between writes leaves access denied. Never reuse
revisions or repair missing adopted controls around retained credentials. Isolate
damaged records so healthy management and revocation remain available.

`resolve` takes the selected owner's current grant to the authenticated actor in
the current provider namespace. Owned selection uses no grant. Applications define
capabilities and map the closed `ConnectionError.code` outcomes. This library
cannot prove provider identity or entitlement for you.

`account_connections.ui` renders escaped native forms and selected-connection
sections. Hosts supply local actions and independently authorize submissions:
browser identity, Origin, fresh authentication where required, expected revisions.

Saved content belongs to the recipient. Revocation stops new protected access;
it does not erase saved content. Work admitted before revoke may finish on its
captured connection subject to native barriers. Continuations must revalidate
captured selection and cannot silently acquire another one.

## Development

Run `uv sync --locked`, then `make check`. Tests are offline and synthetic.
