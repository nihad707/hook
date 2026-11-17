"""Persona: a fake company/server. Derived from the attacker's seed, so every answer inside one session is consistent."""
from __future__ import annotations

import base64
import json
import random
import string
import time

FIRST = ["james", "maria", "li", "olga", "ahmed", "sofia", "david", "anna", "kenji", "laura", "omar", "elena", "pavel", "nina", "tom", "ines"]
LAST = ["smith", "garcia", "wang", "ivanova", "hassan", "rossi", "cohen", "tanaka", "novak", "silva", "khan", "meyer", "kim", "ali", "costa", "dubois"]
COMPANIES = ["acme", "northwind", "contoso", "globex", "initech", "vandelay", "hooli", "soylent", "tyrell", "massive"]
SERVICES = ["auth", "billing", "web", "worker", "redis", "postgres", "nginx", "mailer", "cron", "search", "gateway", "queue"]


def _hex(r, n): return "".join(r.choices("0123456789abcdef", k=n))
def _alnum(r, n, extra=""): return "".join(r.choices(string.ascii_letters + string.digits + extra, k=n))
def _b64url(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def _b64(s: str) -> str: return base64.b64encode(s.encode()).decode()
def _bcrypt(r): return "$2b$12$" + "".join(r.choices(string.ascii_letters + string.digits + "./", k=53))


def _jwt(r, sub, role):
    head = _b64url(b'{"alg":"HS256","typ":"JWT"}')
    now = int(time.time())
    body = _b64url(json.dumps({"sub": sub, "role": role, "iat": now - r.randint(60, 86400), "exp": now + 86400 * 30}).encode())
    return f"{head}.{body}.{_alnum(r, 43, '-_')}"


class Persona:
    """All values are random and fake (AKIA..., sk_live_..., ghp_... are not real credentials)."""

    def __init__(self, seed: int):
        r = random.Random(seed)
        self.seed = seed
        self.company = r.choice(COMPANIES)
        self.service = r.choice(["api", "core", "gateway", "billing", "portal", "backend"])
        self.host = f"{self.company}-{self.service}-{r.randint(1, 9):02d}"
        self.domain = f"{self.company}.internal"
        kind = r.choice(("10", "172", "192"))
        if kind == "10":
            self.subnet = f"10.{r.randint(0, 254)}.{r.randint(0, 254)}"
        elif kind == "172":
            self.subnet = f"172.{r.randint(16, 31)}.{r.randint(0, 254)}"
        else:
            self.subnet = f"192.168.{r.randint(0, 254)}"
        self.db_kind = r.choice(("postgres", "mysql", "mongodb"))
        self.db_port = {"postgres": 5432, "mysql": 3306, "mongodb": 27017}[self.db_kind]
        self.db_host = self.ip(r, 10, 60)
        self.db_name = f"{self.company}_{r.choice(('prod', 'main', 'app'))}"
        self.db_user = r.choice(("app", f"svc_{self.company}", "admin", "readwrite"))
        self.db_pass = _alnum(r, 20, "!#%_-")
        self.redis_host = self.ip(r, 61, 90)
        self.redis_pass = _alnum(r, 24)
        self.jwt_secret = _hex(r, 64)
        self.app_key = "base64:" + base64.b64encode(r.getrandbits(256).to_bytes(32, "big")).decode()
        self.aws_id = "AKIA" + "".join(r.choices(string.ascii_uppercase + string.digits, k=16))
        self.aws_secret = _alnum(r, 40, "+/")
        self.stripe = "sk_live_" + _alnum(r, 24)
        self.admin_token = "hk_adm_" + _hex(r, 40)
        self.gh_token = "ghp_" + _alnum(r, 36)
        self.orchestrator = r.choice(("docker", "k8s"))
        self.orch_ip = self.ip(r, 2, 9)
        self.ns = r.choice(("default", "production", "payments", "backend"))
        self.os = r.choice(("Ubuntu 20.04.6 LTS", "Debian GNU/Linux 11 (bullseye)", "Amazon Linux 2"))
        self.kernel = r.choice(("5.4.0-169-generic", "5.10.0-27-amd64", "4.14.336-257.562.amzn2.x86_64"))
        self.svcs = r.sample(SERVICES, 8)
        self.web_user = r.choice(("www-data", "node", "app"))
        self.app_dir = r.choice(("/var/www/app", "/app", "/srv/app", "/opt/app"))

    def ip(self, r, lo, hi): return f"{self.subnet}.{r.randint(lo, hi)}"

    def containers(self, n):
        r = random.Random(self.seed + 7)
        out = []
        for i in range(n):
            svc = self.svcs[i % len(self.svcs)]
            out.append({"id": _hex(r, 64), "name": f"{self.company}_{svc}_{i // len(self.svcs) + 1}", "svc": svc,
                        "image": f"{self.company}/{svc}:{r.choice(('1.4.2', '2.0.1', 'latest', '3.1.0'))}",
                        "port": r.choice((80, 443, 3000, 5432, 6379, 8080, 9000)), "ip": self.ip(r, 2, 60)})
        return out

    def users(self, start, n):
        out = []
        for i in range(start, start + n):
            r = random.Random(self.seed * 31 + i)
            f, l = r.choice(FIRST), r.choice(LAST)
            out.append({"id": 1000 + i, "email": f"{f}.{l}@{self.company}.example", "role": r.choice(("user", "user", "user", "support", "admin")),
                        "password_hash": _bcrypt(r), "api_token": "tok_" + _hex(r, 32), "created_at": f"202{r.randint(1, 5)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"})
        return out

    def env_pairs(self):
        pairs = [("APP_NAME", f"{self.company}-{self.service}"), ("APP_ENV", "production"), ("APP_DEBUG", "true"), ("APP_KEY", self.app_key),
                 ("DB_CONNECTION", self.db_kind), ("DB_HOST", self.db_host), ("DB_PORT", str(self.db_port)), ("DB_DATABASE", self.db_name),
                 ("DB_USERNAME", self.db_user), ("DB_PASSWORD", self.db_pass), ("REDIS_HOST", self.redis_host), ("REDIS_PASSWORD", self.redis_pass),
                 ("JWT_SECRET", self.jwt_secret), ("ADMIN_API_TOKEN", self.admin_token), ("AWS_ACCESS_KEY_ID", self.aws_id),
                 ("AWS_SECRET_ACCESS_KEY", self.aws_secret), ("AWS_DEFAULT_REGION", "eu-central-1"), ("S3_BUCKET", f"{self.company}-prod-backups"),
                 ("STRIPE_SECRET", self.stripe)]
        pairs.append(("K8S_API_SERVER", f"https://{self.orch_ip}:6443") if self.orchestrator == "k8s" else ("DOCKER_HOST", f"tcp://{self.orch_ip}:2375"))
        return pairs
