# Authority storage platforms

The canonical authority backend remains POSIX-only. Importing the pure rules or
optional people, controls and migration modules does not load `fcntl` or create
state. Constructing a store on an unqualified platform raises
`StateError("unsupported_storage_platform")` before creating its root. Applications
must retain their existing portable authority until a complete backend qualifies.

The internal backend owns private directory validation and creation, private file
opens, shared/exclusive process locks, atomic replacement and durable removal.
Storage, operation fences and inactive-person readmission use the same boundary.
An alternative backend cannot substitute an in-process lock, treat shared work as
unlocked, or implement only `fcntl` replacement. Nested shared work may not upgrade
to a writer; exclusive work may contain shared work. Operation locks precede the
short reentrant authority transaction, and release on abrupt process exit.

POSIX verification includes independent spawned processes for all conflicting lock
modes, concurrent record updates, abrupt writer exit, and disconnect draining before
provider deletion. Writes flush the temporary file before atomic replacement and
then flush its parent directory. Removal also flushes the parent directory.

Windows is deliberately unregistered. Before registering it, qualify an equivalent
owned private ACL policy, handle-based reparse-point refusal, process locks, atomic
durable replacement/removal and restart recovery on a native Windows filesystem.
Run the application conformance and installed-wheel checks there as well. Simulated
platform selection and a Linux pass do not establish Windows compatibility.

## Qualifying an unregistered candidate

The native process suite can select a test-only zero-argument factory without
changing production registration:

```sh
uv run --locked pytest -q tests/test_platform_storage.py \
  --authority-test-backend=account_connections._posix:PosixBackend
```

Replace the factory with the candidate's importable `MODULE:FACTORY` on its native
platform. Every spawned process constructs that same backend independently; an
override in the parent alone does not test cross-process behavior. The production
selector still refuses unsupported platforms. Without an explicit candidate, the
native tests run on POSIX and skip on unqualified systems. The POSIX directory-flush
instrumentation is separate and remains POSIX-only. Lock deadlines and crash/drain
assertions are unchanged.

Identifier vectors require independent records, initialization markers and discovery
for case variants, reserved Windows device names, trailing dots and maximum-length
IDs. They are conformance requirements, not a Windows filename implementation.
The current layout uses exact IDs in physical names and discovery uses filesystem
paths directly. A Windows candidate must first specify a case-safe physical layout,
including marker, snapshot and migration names, route existence/discovery through
that layout, and define explicit adoption of retained state. Do not silently
normalize exact identity IDs or reinterpret existing authority.

Candidate qualification also needs native security and persistence checks beyond
this suite: protected owned ACLs on existing and newly created objects; ancestor and
final reparse-point replacement races checked through handles; safe descriptor
ownership; and atomic replacement/removal with a documented directory-entry
durability or recovery contract. File flush plus rename alone is not evidence of
equivalent directory-entry durability. Process-crash tests do not establish
power-loss safety. Keep Windows unregistered until those checks, native application
conformance and a clean installed-wheel run pass on the supported filesystem.
