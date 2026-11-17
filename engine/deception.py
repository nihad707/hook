"""Entry point of the deception engine: (state, request) -> fake response. Pure, no I/O."""
from __future__ import annotations

import hashlib
import random
from urllib.parse import parse_qs

from core.config import settings

from .persona import Persona
from .routing import VECTORS, pick_vector
from .vectors import Ctx

# A WAF answers 403/429 and thereby reveals itself. The engine never does: this set is a hard guard.
FORBIDDEN_STATUSES = frozenset({403, 429})


def persona_label(seed: int) -> str:
    pe = Persona(seed)
    return f"{pe.host} / {pe.subnet}.0/24"


def compute_delay(level: int) -> int:
    """Believable latency (never instant) + exponential tarpit hint that the SDK applies without blocking the app."""
    delay = random.randint(30, 160)
    if level:
        delay += int(min(settings.TARPIT_MAX_MS, 250 * 1.55 ** (level - 1)) * random.uniform(0.75, 1.25))
    return min(delay, settings.TARPIT_MAX_MS)


def deceive(st, path: str, query: str, method: str):
    c = Ctx()
    c.st, c.path, c.query, c.method, c.atype, c.stage = st, path, query, method, st.atype, st.stage
    c.q = parse_qs(query, keep_blank_values=True, max_num_fields=30)
    c.p = Persona(st.seed)
    c.r = random.Random(int.from_bytes(hashlib.sha256(f"{st.seed}|{path}|{st.stage}".encode()).digest()[:8], "big"))
    c.scale = min(1 + st.stage // 8 + st.tarpit, 8)       # deeper session / bigger flood -> bigger, more tangled answers
    name = pick_vector(c)
    status_code, ctype, body = VECTORS[name](c)
    if status_code in FORBIDDEN_STATUSES:
        status_code = 200
    return name, status_code, ctype, body
