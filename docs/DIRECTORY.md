# Optional exact-subject directory transport

`account_connections.directory.ExactSubjectDirectory` implements the existing
`Callable[Identity, DirectoryPerson | None]` hook. It adds no roster discovery,
person mapping, positive cache, browser identity verification or readmission.
The application supplies the configured verified issuer, a fixed HTTPS directory
base URL, and one independently scoped API key from private configuration.

The only request is `GET <configured-prefix>/users/<immutable-subject>` with
`X-API-Key`; an optional prefix supports separately configured reverse proxies.
Issuer comparison is exact. Subjects must match `[A-Za-z0-9_-]{1,200}` and are
sent raw, never encoded. Configuration rejects URL credentials, queries,
fragments, encoded paths and noncanonical path segments. Connections use the
system certificate trust store and connect directly; environment proxy settings,
ambient credentials, cookies, redirects and response compression are not used.

The JSON object must contain exactly `displayName`, `disabled` and `admitted`.
Duplicate fields, extra/missing fields, nonboolean admission fields, invalid or
oversized labels and wrong content types are unavailable responses. A person is
admitted only when `admitted is True` and `disabled is False`. Display names are
labels, never identity evidence. The existing people layer still sanitizes them
for presentation.

HTTP bodies may use a content length, connection close, or chunked framing.
Conflicting length/transfer headers and unsupported transfer encodings are
unavailable responses; the complete bounded body must be valid JSON.

The default body limit is 8 KiB and the maximum configured limit is 64 KiB.
The default caller deadline is three seconds, configurable up to 30 seconds.
It includes resolution, connection, headers and body. Socket-operation timeouts
also shrink to the remaining monotonic budget. There are no automatic retries,
executor shutdown waits or persistent connections.

Each instance allows at most four in-flight daemon workers by default,
configurable from one to 32. Saturated capacity fails immediately. An operating
system resolver or other stalled operation can outlive the caller's deadline,
but retains its slot until it exits; repeated failures cannot spawn unbounded
threads. Its late result is discarded. Resolution that finishes too late cannot
send an authenticated request. All concurrent users of one scoped client should
reuse one transport instance, rather than creating instances per request.

A valid negative verdict returns `DirectoryPerson(False, label)`; HTTP 404
returns `None`. Authentication failures, outages, redirects and malformed
responses raise `DirectoryUnavailable` with the fixed message
`directory_unavailable`, without remote error text. The people layer maps this
to its existing unavailable error without
turning an outage into durable person departure. Valid departure still follows
the existing inactive/forgotten authority rules; a positive lookup cannot readmit
an inactive person.

This optional module does not activate a directory, generate keys, change client
policies or add ingress. Consumer wiring
requires separately reviewed restricted-client policy, independent keys, the
identity directory deployment, and applicable consumer release/production gates.
