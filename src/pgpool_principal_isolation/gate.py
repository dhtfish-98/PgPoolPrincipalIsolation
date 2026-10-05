"""Downstream application pool guard; it does not modify or replace PgCat.

The caller must provide an already authenticated principal. A lease exposes only
fixed read operations so callers cannot terminate its checked transaction.
"""

from __future__ import annotations

from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import RLock
from typing import Iterator, Mapping

import psycopg
from psycopg import sql


class Unauthorized(PermissionError):
    """The verified principal has no binding to this database."""


class PrincipalMismatch(PermissionError):
    """The actual PostgreSQL session is not the requested binding."""


class GateClosed(RuntimeError):
    """This pool or lease is no longer usable."""


@dataclass(frozen=True)
class Binding:
    principal: str
    database: str
    role: str
    password: str = field(repr=False)
    host: str = "127.0.0.1"
    port: int = 6432

    def __post_init__(self) -> None:
        if not all((self.principal, self.database, self.role, self.password, self.host)):
            raise ValueError("binding fields must be nonempty")
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid PostgreSQL port")


@dataclass(frozen=True)
class Probe:
    current_user: str
    session_user: str
    database: str
    backend_pid: int


class ReadLease:
    """Only fixed, read-only queries are exposed inside the checked transaction."""

    def __init__(self, connection: psycopg.Connection, probe: Probe) -> None:
        self._connection = connection
        self._probe = probe
        self._active = True

    @property
    def identity(self) -> Probe:
        if not self._active:
            raise GateClosed("lease has ended")
        return self._probe

    def read_secret(self, schema: str) -> list[str]:
        """Read the owned lab fixture table in a safely quoted schema."""
        if not self._active:
            raise GateClosed("lease has ended")
        if not isinstance(schema, str) or not schema:
            raise ValueError("schema must be a nonempty string")
        statement = sql.SQL("SELECT token FROM {}.secret ORDER BY token").format(sql.Identifier(schema))
        rows = self._connection.execute(statement).fetchall()
        return [str(row[0]) for row in rows]

    def _end(self) -> None:
        self._active = False


class PrincipalPool:
    """Key by verified principal and database; recheck backend inside each transaction."""

    def __init__(self, bindings: Mapping[tuple[str, str], Binding], max_idle: int = 2) -> None:
        if max_idle < 0:
            raise ValueError("max_idle must be nonnegative")
        self._bindings = self._checked_bindings(bindings)
        self._max_idle = max_idle
        self._idle: dict[tuple[str, str], list[psycopg.Connection]] = defaultdict(list)
        self._epoch = 0
        self._closed = False
        self._lock = RLock()

    @staticmethod
    def _checked_bindings(bindings: Mapping[tuple[str, str], Binding]) -> dict[tuple[str, str], Binding]:
        checked = dict(bindings)
        for key, binding in checked.items():
            if key != (binding.principal, binding.database):
                raise ValueError("binding key differs from verified principal and database")
        return checked

    def reload(self, bindings: Mapping[tuple[str, str], Binding]) -> None:
        """Atomically swap policy and drain idle connections; active leases finish normally."""
        checked = self._checked_bindings(bindings)
        with self._lock:
            if self._closed:
                raise GateClosed("pool is closed")
            old = self._idle
            self._idle = defaultdict(list)
            self._bindings = checked
            self._epoch += 1
        for conns in old.values():
            for conn in conns:
                conn.close()

    def close(self) -> None:
        with self._lock:
            old = self._idle
            self._idle = defaultdict(list)
            self._closed = True
            self._epoch += 1
        for conns in old.values():
            for conn in conns:
                conn.close()

    @contextmanager
    def checkout(self, verified_principal: str, database: str) -> Iterator[ReadLease]:
        """Pin and verify a backend before handing the lease to read-only code."""
        key = (verified_principal, database)
        with self._lock:
            if self._closed:
                raise GateClosed("pool is closed")
            binding = self._bindings.get(key)
            if binding is None:
                raise Unauthorized("principal/database binding is absent")
            epoch = self._epoch
            conn = self._idle[key].pop() if self._idle[key] else None
        if conn is None:
            conn = psycopg.connect(
                host=binding.host,
                port=binding.port,
                dbname=binding.database,
                user=binding.role,
                password=binding.password,
                connect_timeout=5,
                autocommit=True,
                application_name="pgpool-principal-isolation",
            )
        reusable = False
        lease: ReadLease | None = None
        try:
            with conn.transaction():
                conn.execute("SET TRANSACTION READ ONLY")
                row = conn.execute(
                    "SELECT current_user::text, session_user::text, current_database()::text, pg_backend_pid()"
                ).fetchone()
                if row is None:
                    raise PrincipalMismatch("identity query produced no row")
                probe = Probe(*row)
                if (probe.current_user, probe.session_user, probe.database) != (
                    binding.role, binding.role, binding.database
                ):
                    raise PrincipalMismatch("backend identity differs from verified binding")
                with self._lock:
                    if self._closed or self._epoch != epoch or self._bindings.get(key) != binding:
                        raise Unauthorized("binding changed during checkout")
                lease = ReadLease(conn, probe)
                try:
                    yield lease
                finally:
                    lease._end()
            reusable = True
        finally:
            with self._lock:
                can_reuse = (
                    reusable
                    and not self._closed
                    and self._epoch == epoch
                    and self._bindings.get(key) == binding
                    and not conn.closed
                    and len(self._idle[key]) < self._max_idle
                )
                if can_reuse:
                    self._idle[key].append(conn)
            if not can_reuse:
                conn.close()
