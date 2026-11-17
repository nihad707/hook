"""Deception engine. Importing this package pulls in only pure-Python parts (no FastAPI / SQLAlchemy).
`engine.events` (database write-behind) is imported explicitly by the routers."""
from .deception import compute_delay, deceive, persona_label
from .routing import classify
from .state import AttackState, state_store

__all__ = ["deceive", "classify", "compute_delay", "persona_label", "AttackState", "state_store"]
