# Working on account-connections

This source is published. Use synthetic identities and fixtures; keep credentials,
personal data and deployment details out of code, docs and commit messages.

The library owns grant/selection decisions and presentation only. Applications own
identity verification, eligibility, storage transactions, native credential barriers
and provider capability policy. Never add implicit fallback or credential acquisition.
Run `make check` and built-wheel acceptance. Changes to grants need an independent
commit-range review before landing. `AGENTS.md` is the only agent guide.
