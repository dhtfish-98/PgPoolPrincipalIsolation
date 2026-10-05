# Origin and authorship

- New guard, tests, fixture orchestration and documentation: dhtfish98, 2026, MIT.
- Reference only: `postgresml/pgcat@5b038813eb14f181434ab7b5509e74d9b1fe123b` (2025-02-27). Its MIT license names **Copyright (c) 2023 PgCat Contributors**. The fixed source is built only in the isolated Build environment for live verification. No PgCat source is copied into this package, and no upstream vulnerability is claimed.
- Reference/runtime only: PostgreSQL 17.6, built from the official source archive in Build. PostgreSQL remains under its own license. No PostgreSQL source or binary is shipped in this project package.
- Python dependency: Psycopg and Psycopg Binary 3.3.6, installed separately in the isolated Build environment; their package metadata says `LGPL-3.0-only`. The package declares them as dependencies and does not copy their implementation into its source tree.

The project is a narrow downstream authorization experiment. The test-only weak pool is deliberately invented to establish a contrast. The fixed upstream reference does not imply a PgCat defect, exploit, or security advisory.
