"""Deception vectors. Each returns (http_status_for_attacker, content_type, body[str | dict | list]).

Every answer is believable, fake, and links to the next fake discovery (`_crumbs`).
Nothing here ever returns 403/429 - see `engine.deception.deceive`, which also enforces that.
"""
from __future__ import annotations

import json
import re
import time

from .persona import FIRST, LAST, _alnum, _b64, _hex, _jwt


class Ctx:
    __slots__ = ("p", "r", "st", "stage", "scale", "path", "query", "method", "atype", "q")


def _crumbs(c, n=2):
    pool = ["/api/v2/internal/exec?cmd=id", "/api/v1/debug", "/admin/db_dump.sql", "/.git/config", "/actuator/env",
            "/containers/json", f"/api/v1/namespaces/{c.p.ns}/secrets", "/api/v1/users?page=1", "/server-status"]
    return c.r.sample(pool, n)


def v_env(c):
    p, r = c.p, c.r
    lines = [f"{k}={v}" for k, v in p.env_pairs()]
    for i in range(min(c.scale * 2, 16)):
        lines.append(f"{r.choice(('PAYMENTS', 'MAILER', 'SEARCH', 'REPORTING', 'AUTH'))}_{i}_URL=http://{p.ip(r, 2, 90)}:{r.choice((3000, 8080, 9000))}")
    return 200, "text/plain; charset=utf-8", "\n".join(lines) + "\n"


def v_config(c):
    p = c.p
    return 200, "application/json", {
        "app": {"name": f"{p.company}-{p.service}", "env": "production", "debug": True, "host": p.host},
        "database": {"engine": p.db_kind, "host": p.db_host, "port": p.db_port, "name": p.db_name, "user": p.db_user, "password": p.db_pass},
        "auth": {"jwt_secret": p.jwt_secret, "admin_api_key": p.admin_token, "token": _jwt(c.r, "admin", "superuser")},
        "storage": {"s3": {"bucket": f"{p.company}-prod-backups", "access_key": p.aws_id, "secret_key": p.aws_secret}},
        "services": {"redis": f"redis://:{p.redis_pass}@{p.redis_host}:6379/0", "orchestrator": p.orch_ip},
        "_next": _crumbs(c)}


def v_sql_dump(c):
    p, r = c.p, c.r
    n = min(4 + c.scale * 5, 50)
    dialect = "PostgreSQL database dump" if p.db_kind == "postgres" else "MySQL dump 10.13"
    out = [f"-- {dialect}", f"-- Host: {p.db_host}    Database: {p.db_name}", f"-- Dumped at {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
           "CREATE TABLE users (id integer PRIMARY KEY, email varchar(255) NOT NULL, role varchar(20), password_hash varchar(60), api_token varchar(40), created_at date);", ""]
    for u in p.users(r.randint(0, 400), n):
        out.append(f"INSERT INTO users VALUES ({u['id']}, '{u['email']}', '{u['role']}', '{u['password_hash']}', '{u['api_token']}', '{u['created_at']}');")
    out += ["", "CREATE TABLE api_tokens (id integer, owner varchar(80), token varchar(64), scope varchar(30));"]
    for i in range(min(3 + c.scale, 12)):
        out.append(f"INSERT INTO api_tokens VALUES ({i + 1}, 'svc-{r.choice(p.svcs)}', '{_hex(r, 40)}', '{r.choice(('read', 'write', 'admin'))}');")
    out.append(f"INSERT INTO api_tokens VALUES (99, 'root', '{p.admin_token}', 'admin');")
    out.append(f"-- more: {_crumbs(c, 1)[0]}")
    return 200, "text/plain; charset=utf-8", "\n".join(out) + "\n"


def v_debug(c):
    p, r = c.p, c.r
    db_url = f"{p.db_kind}://{p.db_user}:{p.db_pass}@{p.db_host}:{p.db_port}/{p.db_name}"
    return 200, "application/json", {
        "debug": True, "service": f"{p.company}-{p.service}", "version": f"{r.randint(1, 4)}.{r.randint(0, 9)}.{r.randint(0, 20)}", "hostname": p.host,
        "uptime_s": r.randint(10_000, 9_000_000), "os": p.os,
        "env": {"DATABASE_URL": db_url, "SECRET_KEY": p.jwt_secret, "AWS_ACCESS_KEY_ID": p.aws_id},
        "last_error": {"type": "ConnectionResetError", "trace": [f"File \"{p.app_dir}/server/db.py\", line {r.randint(20, 200)}, in connect", f"File \"{p.app_dir}/server/pool.py\", line {r.randint(20, 200)}, in acquire"]},
        "internal": {"orchestrator": f"{p.orchestrator}://{p.orch_ip}", "admin_token": p.admin_token},
        "routes": ["/api/v1/users", "/api/v2/internal/exec", "/admin/db_dump.sql", "/api/v1/jobs/{id}"], "hint": _crumbs(c, 2)}


def _fake_cmd(c, cmd: str):
    """Pure text emulation. Nothing is ever executed."""
    p, r = c.p, c.r
    cmd = cmd.strip()
    first = cmd.split()[0] if cmd.split() else ""
    if cmd in ("id", "whoami") or first == "id":
        return (f"uid=33({p.web_user}) gid=33({p.web_user}) groups=33({p.web_user})" if cmd != "whoami" else p.web_user), 0
    if first == "hostname": return p.host, 0
    if first == "uname": return f"Linux {p.host} {p.kernel} #1 SMP x86_64 GNU/Linux", 0
    if first == "pwd": return p.app_dir, 0
    if first in ("ls", "dir"): return "\n".join([".env", "config.json", "package.json", "server", "node_modules", "backups", "logs"]), 0
    if first in ("env", "printenv"): return "\n".join(f"{k}={v}" for k, v in p.env_pairs()), 0
    if first in ("ifconfig", "ip"): return f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet {p.ip(r, 100, 120)}  netmask 255.255.255.0", 0
    if "passwd" in cmd: return f"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n{p.web_user}:x:33:33:{p.web_user}:{p.app_dir}:/usr/sbin/nologin\nbackup:x:34:34:backup:/var/backups:/usr/sbin/nologin", 0
    if ".env" in cmd: return "\n".join(f"{k}={v}" for k, v in p.env_pairs()), 0
    if not first: return "", 0
    return f"sh: 1: {first}: not found", 127


def v_exec(c):
    cmd = (c.q.get("cmd") or c.q.get("command") or c.q.get("exec") or c.q.get("c") or [""])[0][:200]
    if not cmd:
        return 200, "application/json", {"error": "missing parameter 'cmd'", "usage": "GET /api/v2/internal/exec?cmd=<command>", "shell": "/bin/sh", "user": c.p.web_user}
    out, code = _fake_cmd(c, cmd)
    return 200, "application/json", {"command": cmd, "stdout": out if code == 0 else "", "stderr": out if code else "", "exit_code": code, "duration_ms": c.r.randint(3, 90)}


def v_docker(c):
    p, r = c.p, c.r
    path = c.path.lower()
    if path.endswith("/_ping"): return 200, "text/plain; charset=utf-8", "OK"
    cs = p.containers(min(4 + c.scale, 12))
    if path.endswith("/images/json"):
        return 200, "application/json", [{"Id": "sha256:" + _hex(r, 64), "RepoTags": [x["image"]], "Size": r.randint(40_000_000, 900_000_000)} for x in cs]
    if path.endswith("/info"):
        return 200, "application/json", {"Containers": len(cs), "ContainersRunning": len(cs) - 1, "Images": len(cs) + 3, "Name": p.host,
                                         "ServerVersion": "20.10.24", "OperatingSystem": p.os, "KernelVersion": p.kernel, "Swarm": {"LocalNodeState": "inactive"}}
    m = re.search(r"/containers/([0-9a-f]{6,64})/json", path)
    if m:
        k = next((x for x in cs if x["id"].startswith(m.group(1))), cs[0])
        env = [f"{a}={b}" for a, b in p.env_pairs()[:9]]
        return 200, "application/json", {"Id": k["id"], "Name": "/" + k["name"], "State": {"Status": "running", "Running": True},
                                         "Config": {"Image": k["image"], "Env": env, "Cmd": ["node", "server.js"]}, "NetworkSettings": {"IPAddress": k["ip"]}}
    if "/containers" in path:
        return 200, "application/json", [{"Id": x["id"], "Names": ["/" + x["name"]], "Image": x["image"], "State": "running", "Status": f"Up {r.randint(1, 40)} days",
                                          "Ports": [{"IP": "0.0.0.0", "PrivatePort": x["port"], "PublicPort": x["port"], "Type": "tcp"}],
                                          "NetworkSettings": {"Networks": {"bridge": {"IPAddress": x["ip"]}}}} for x in cs]
    return v_orch_version(c)


def v_k8s(c):
    p, r = c.p, c.r
    path = c.path.lower().rstrip("/")
    cs = p.containers(min(4 + c.scale, 12))
    if path == "/api": return 200, "application/json", {"kind": "APIVersions", "versions": ["v1"], "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": f"{p.orch_ip}:6443"}]}
    if path == "/apis": return 200, "application/json", {"kind": "APIGroupList", "groups": [{"name": n, "preferredVersion": {"groupVersion": f"{n}/v1"}} for n in ("apps", "batch", "networking.k8s.io", "rbac.authorization.k8s.io")]}
    if path == "/api/v1": return 200, "application/json", {"kind": "APIResourceList", "groupVersion": "v1", "resources": [{"name": n, "namespaced": True} for n in ("pods", "secrets", "services", "configmaps")]}
    if path.endswith("/namespaces") or path.endswith("/nodes"):
        names = ["default", "kube-system", p.ns, "monitoring", "ingress-nginx"] if path.endswith("/namespaces") else [f"{p.company}-node-{i}" for i in range(1, 4)]
        return 200, "application/json", {"kind": "List", "apiVersion": "v1", "items": [{"metadata": {"name": n, "uid": str(r.getrandbits(64))}} for n in names]}
    if path.endswith("/secrets"):
        items = [("db-credentials", {"username": p.db_user, "password": p.db_pass}), ("jwt-signing", {"secret": p.jwt_secret}),
                 ("aws-creds", {"AWS_ACCESS_KEY_ID": p.aws_id, "AWS_SECRET_ACCESS_KEY": p.aws_secret}),
                 ("registry-auth", {".dockerconfigjson": json.dumps({"auths": {f"registry.{p.domain}": {"auth": _b64(f"ci:{_alnum(r, 20)}")}}})})]
        return 200, "application/json", {"kind": "SecretList", "apiVersion": "v1", "items": [
            {"metadata": {"name": n, "namespace": p.ns}, "type": "Opaque", "data": {k: _b64(v) for k, v in d.items()}} for n, d in items[:min(2 + c.scale, 4)]]}
    if path.endswith("/pods") or "/pods" in path:
        return 200, "application/json", {"kind": "PodList", "apiVersion": "v1", "items": [
            {"metadata": {"name": f"{x['name']}-{_hex(r, 5)}", "namespace": p.ns}, "status": {"phase": "Running", "podIP": x["ip"]}, "spec": {"containers": [{"name": x["svc"], "image": x["image"]}]}} for x in cs]}
    return v_orch_version(c)


def v_orch_version(c):
    p, r = c.p, c.r
    if p.orchestrator == "k8s":
        return 200, "application/json", {"major": "1", "minor": "27", "gitVersion": f"v1.27.{r.randint(3, 11)}", "platform": "linux/amd64"}
    return 200, "application/json", {"Platform": {"Name": "Docker Engine - Community"}, "Version": "20.10.24", "ApiVersion": "1.41", "Os": "linux", "Arch": "amd64", "KernelVersion": p.kernel}


def v_login(c):
    """Brute-force lure: fails 6-14 times, then "succeeds" with a redirect to a deeper lure, then restarts.
    The counters live on the shared state object and are persisted to Redis by the trap router."""
    st, p, r = c.st, c.p, c.r
    if c.method == "GET":
        return 200, "text/html; charset=utf-8", f"<!doctype html><title>{p.company} admin</title><form method=post action=/login><input name=username><input name=password type=password><button>Sign in</button></form>"
    st.login_attempts += 1
    if st.login_goal == 0:
        st.login_goal = r.randint(6, 14)
    if st.login_attempts >= st.login_goal:
        st.login_attempts, st.login_goal = 0, 0
        return 200, "application/json", {"success": True, "token": _jwt(r, "admin", "superuser"), "role": "superuser", "redirect": r.choice(["/admin/db_dump.sql", "/api/v2/internal/exec", "/api/v1/debug"])}
    return 401, "application/json", {"success": False, "error": r.choice(["Invalid credentials", "Invalid username or password", "Authentication failed"])}


def v_robots(c):
    r = c.r
    if "sitemap" in c.path.lower():
        urls = "".join(f"<url><loc>/archive/{r.randint(1, 99999)}/{r.choice(FIRST)}-{r.choice(LAST)}</loc></url>" for _ in range(min(30 + c.scale * 10, 100)))
        return 200, "application/xml", f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}<url><loc>/sitemap-{r.randint(2, 9999)}.xml</loc></url></urlset>'
    return 200, "text/plain; charset=utf-8", "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /api/v2/internal/\nDisallow: /.git/\nDisallow: /api/v1/exports/\nSitemap: /sitemap.xml\n"


def v_items(c):
    p = c.p
    try:
        page = max(1, min(int((c.q.get("page") or ["1"])[0]), 10_000_000))
    except ValueError:
        page = 1
    per = min(10 + c.scale * 3, 40)
    rows = p.users((page - 1) * per, per)
    return 200, "application/json", {"data": rows, "page": page, "per_page": per, "total": 9_999_999, "has_more": True,
                                    "next": f"{c.path}?page={page + 1}", "export": f"/api/v1/exports/{_hex(c.r, 10)}.sql"}


def v_job(c):
    r = c.r
    done = r.random() < 0.18
    body = {"job_id": _hex(r, 12), "status": "completed" if done else "running", "progress": 100 if done else r.randint(5, 97), "eta_seconds": 0 if done else r.randint(3, 40)}
    body["result_url" if done else "poll_url"] = f"/api/v1/exports/{_hex(r, 10)}.sql" if done else f"/api/v1/jobs/{_hex(r, 12)}"
    return 200, "application/json", body


def v_git(c):
    p = c.p
    return 200, "text/plain; charset=utf-8", (f"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://deploy:{p.gh_token}@github.com/{p.company}/{p.service}-prod.git\n"
                                               "\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n")


def v_actuator(c):
    p = c.p
    return 200, "application/json", {"activeProfiles": ["prod"], "propertySources": [{"name": "systemEnvironment", "properties": {
        "DB_PASSWORD": {"value": p.db_pass}, "JWT_SECRET": {"value": "******"}, "SPRING_DATASOURCE_URL": {"value": f"jdbc:{p.db_kind}://{p.db_host}:{p.db_port}/{p.db_name}"},
        "AWS_ACCESS_KEY_ID": {"value": p.aws_id}}}], "_links": _crumbs(c, 2)}


def v_status(c):
    p, r = c.p, c.r
    rows = "".join(f"<tr><td>{i}</td><td>{r.randint(1000, 30000)}</td><td>{p.ip(r, 100, 200)}</td><td>GET {r.choice(('/api/v1/users', '/admin/db_dump.sql', '/api/v2/internal/exec', '/.env'))} HTTP/1.1</td></tr>" for i in range(min(8 + c.scale * 2, 30)))
    return 200, "text/html; charset=utf-8", f"<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for {p.host}</h1><dl><dt>Server Version: Apache/2.4.49 ({p.os})</dt></dl><table border=1><tr><th>Srv</th><th>PID</th><th>Client</th><th>Request</th></tr>{rows}</table></body></html>"
