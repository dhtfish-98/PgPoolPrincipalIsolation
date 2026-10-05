from contextlib import contextmanager

import pytest

from pgpool_principal_isolation import Binding, GateClosed, PrincipalMismatch, PrincipalPool, Unauthorized
from pgpool_principal_isolation import gate


class FakeResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row

    def fetchall(self):
        return [self.row]


class FakeConnection:
    def __init__(self, role="lab_alpha", database="lab_alpha", session_role=None, on_identity=None):
        self.role = role
        self.session_role = session_role or role
        self.database = database
        self.on_identity = on_identity
        self.closed = False
        self.statements = []

    @contextmanager
    def transaction(self):
        yield

    def execute(self, statement, params=None):
        self.statements.append(str(statement))
        if "current_user" in str(statement):
            if self.on_identity is not None:
                self.on_identity()
            return FakeResult((self.role, self.session_role, self.database, 123))
        return FakeResult(("alpha-marker",))

    def close(self):
        self.closed = True


def binding(role="lab_alpha", database="lab_alpha"):
    return Binding(role, database, role, "synthetic-password")


def test_unbound_pair_rejected_before_connect(monkeypatch):
    monkeypatch.setattr(gate.psycopg, "connect", lambda **kwargs: pytest.fail("must not connect"))
    pool = PrincipalPool({("lab_alpha", "lab_alpha"): binding()})
    with pytest.raises(Unauthorized), pool.checkout("lab_beta", "lab_alpha"):
        pass


def test_checked_transaction_reuses_only_matching_idle_connection(monkeypatch):
    conn = FakeConnection()
    calls = []

    def connect(**kwargs):
        calls.append(kwargs)
        return conn

    monkeypatch.setattr(gate.psycopg, "connect", connect)
    pool = PrincipalPool({("lab_alpha", "lab_alpha"): binding()})
    with pool.checkout("lab_alpha", "lab_alpha") as lease:
        assert lease.identity.current_user == "lab_alpha"
        assert lease.read_secret("alpha") == ["alpha-marker"]
    with pytest.raises(GateClosed):
        lease.read_secret("alpha")
    with pool.checkout("lab_alpha", "lab_alpha") as lease2:
        assert lease2.identity.backend_pid == 123
    assert len(calls) == 1
    assert len([statement for statement in conn.statements if "current_user" in statement]) == 2
    pool.close()
    assert conn.closed


@pytest.mark.parametrize(
    ("actual_role", "session_role", "actual_database"),
    [
        ("lab_alpha", "lab_alpha", "lab_alpha"),
        ("lab_beta", "lab_alpha", "lab_alpha"),
        ("lab_beta", "lab_beta", "lab_beta"),
    ],
)
def test_poisoned_idle_connection_denied_before_lease(monkeypatch, actual_role, session_role, actual_database):
    alpha = FakeConnection(actual_role, actual_database, session_role)
    monkeypatch.setattr(gate.psycopg, "connect", lambda **kwargs: alpha)
    beta = binding("lab_beta", "lab_alpha")
    pool = PrincipalPool({("lab_beta", "lab_alpha"): beta})
    with pytest.raises(PrincipalMismatch), pool.checkout("lab_beta", "lab_alpha"):
        pytest.fail("wrong-role backend reached caller")
    assert alpha.closed


def test_reload_drains_idle_connection(monkeypatch):
    conn = FakeConnection()
    monkeypatch.setattr(gate.psycopg, "connect", lambda **kwargs: conn)
    item = binding()
    pool = PrincipalPool({("lab_alpha", "lab_alpha"): item})
    with pool.checkout("lab_alpha", "lab_alpha"):
        pass
    pool.reload({("lab_alpha", "lab_alpha"): item})
    assert conn.closed


def test_reload_during_identity_probe_denies_stale_checkout(monkeypatch):
    item = binding()
    pool = PrincipalPool({("lab_alpha", "lab_alpha"): item})
    conn = FakeConnection(on_identity=lambda: pool.reload({}))
    monkeypatch.setattr(gate.psycopg, "connect", lambda **kwargs: conn)
    with pytest.raises(Unauthorized), pool.checkout("lab_alpha", "lab_alpha"):
        pytest.fail("stale policy reached caller")
    assert conn.closed


def test_binding_never_displays_password():
    assert "synthetic-password" not in repr(binding())
    with pytest.raises(ValueError):
        PrincipalPool({("lab_alpha", "wrong"): binding()})
