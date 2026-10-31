# account-connections

Small Python rules for letting authenticated people explicitly use a connection
its owner shared with them. No credentials, network clients or storage framework.

Owners offer access. Recipients choose in one action and can switch between owned
and shared connections, including after disconnecting their own. Offers never
change routing. Revoke, leave and scope changes never fall back. Reissued grants
have new revisions; an old selection cannot regain access.

## Host contract

The host authenticates the actor, checks current application membership, selects
the provider namespace and loads strictly validated native records. The actor and
owner come from those bindings, never an untrusted tool parameter. Only owners
may acquire credentials, disconnect or offer access. Recipients cannot reshare.

Call `offer`, `choose`, `resolve`, `revoke` and `leave` under the application's
shared authority lock. Persist returned state before success. Do not hold that
lock across network/browser work. Capture immutable admission per operation;
recheck native barriers at actual credential access and publication. Admission
never overrides session generations, holds, budgets or profile leases.

Revoke durably before clearing a departing selection, holding the transaction
lock throughout. A crash between writes leaves access denied. Never reuse
revisions or repair missing adopted controls around retained credentials. Isolate
damaged records so healthy management and revocation remain available.

`resolve` takes the selected owner's current grant to the authenticated actor in
the current provider namespace. Owned selection uses no grant. Applications define
capabilities and map the closed `ConnectionError.code` outcomes. This library
cannot prove identity, storage integrity or provider entitlement for you.

`account_connections.ui` renders escaped native forms and selected-connection
sections. Hosts supply local actions and independently authorize submissions:
browser identity, Origin, fresh authentication where required, expected revisions.

Saved content belongs to the recipient. Revocation stops new protected access;
it does not erase saved content. Work admitted before revoke may finish on its
captured connection subject to native barriers. Continuations must revalidate
captured selection and cannot silently acquire another one.

## Development

Run `uv sync --locked`, then `make check`. Tests are offline and synthetic.
