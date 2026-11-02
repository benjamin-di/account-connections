# Platform boundary and directory admission review

Independent local review approved
`de3f2a763a549b6619182a84055540a8b047b787..6a94e22fe73b9468e4ca82f4d8316f7def6f215e`,
tree `6336c5bed1ca07a05acedff40d724ee02235b4f4`, with no findings.

The platform preparation preserves POSIX private storage, transaction and
publication locks, while optional imports avoid loading POSIX primitives on
unsupported systems. Unsupported platforms refuse authority operations before
creating state. This is not a qualified Windows backend.

The optional directory transport binds a verified issuer, immutable subject and
scoped client key to one HTTPS endpoint. It validates the complete bounded
response, fails closed without exposing remote errors, and cannot readmit durable
inactive people. One earlier review finding identified ambiguous HTTP framing:
the corrected source rejects conflicting transfer/length headers and unsupported
transfer encodings before admission JSON is parsed.

Independent verification covered 214 focused tests, nine additional synthetic
HTTPResponse framing probes, Ruff, mypy and range whitespace checks. Author
validation passed the full 316-test gate and 103 installed-wheel transport tests.
Two real HTTPResponse regressions fail against the previous directory source.

This receipt covers local preparation. Exact release qualification, Windows
implementation and native acceptance, and directory activation remain separate.
