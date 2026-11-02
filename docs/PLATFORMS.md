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
