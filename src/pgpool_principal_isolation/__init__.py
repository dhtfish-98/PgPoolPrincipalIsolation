"""Narrow, self-authored read-only PostgreSQL principal binding gate."""

from .gate import Binding, GateClosed, PrincipalMismatch, PrincipalPool, Probe, Unauthorized

__all__ = ["Binding", "GateClosed", "PrincipalMismatch", "PrincipalPool", "Probe", "Unauthorized"]
__version__ = "0.1.0"
