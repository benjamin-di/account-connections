# Working on account-connections

This source is published. Use synthetic identities and fixtures; keep credentials,
personal data and deployment details out of code, docs and commit messages.

The library owns people bindings, namespaced controls, grants, selection, admission,
private control-record transactions and generic management routes. Applications own
identity verification, eligibility, credential formats, provider capability policy,
budgets and caches. Credentials never enter library records; app callbacks publish
them behind the library's fences. Never add implicit fallback or credential acquisition.
Run `make check` and built-wheel acceptance. Changes to grants need an independent
commit-range review before landing. `AGENTS.md` is the only agent guide.
