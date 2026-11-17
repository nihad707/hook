"""Attacker classification and vector selection."""
from __future__ import annotations

import re

from .vectors import (v_actuator, v_config, v_debug, v_docker, v_env, v_exec, v_git, v_items, v_job, v_k8s, v_login,
                      v_orch_version, v_robots, v_sql_dump, v_status)

AI_SIGS = ("gpt-agent", "langchain", "autogen", "openai", "anthropic", "llamaindex", "crewai", "autogpt", "auto-gpt", "ai-agent", "llm")
SCANNER_SIGS = ("nmap", "nikto", "sqlmap", "masscan", "zgrab", "nuclei", "gobuster", "dirb", "wpscan", "ai-scanner", "acunetix",
                "nessus", "openvas", "burp", "ffuf", "feroxbuster")
BRUTE_SIGS = ("hydra", "medusa", "patator", "ncrack")
SCRAPER_SIGS = ("python-requests", "curl", "wget", "scrapy", "httpx", "aiohttp", "go-http-client", "okhttp", "libwww", "bot",
                "spider", "crawl", "headless", "puppeteer", "playwright", "selenium")
LOGIN_RE = re.compile(r"login|signin|sign-in|wp-login|xmlrpc|phpmyadmin|/auth|^/admin/?$")

VECTORS = {"env_file": v_env, "config_json": v_config, "sql_dump": v_sql_dump, "debug_info": v_debug, "exec_shell": v_exec, "docker_api": v_docker,
           "k8s_api": v_k8s, "orch_version": v_orch_version, "login": v_login, "robots_sitemap": v_robots, "paged_items": v_items, "job_poll": v_job,
           "git_config": v_git, "actuator_env": v_actuator, "server_status": v_status}

ROUTES = [(re.compile(rx), name) for rx, name in [
    (r"^/\.env|/\.aws/|/env\.(txt|js)$|/\.npmrc$", "env_file"),
    (r"/\.git/", "git_config"),
    (r"\.(sql|bak|dump)$|/(db_?)?(dump|backup)|^/api/v\d+/exports/", "sql_dump"),
    (r"/config\.(json|ya?ml)$|/settings\.json$|/appsettings", "config_json"),
    (r"/(exec|cmd|shell|console|eval|run)(/|$)", "exec_shell"),
    (r"/debug|/trace|/__debug__", "debug_info"),
    (r"^/actuator", "actuator_env"),
    (r"^/(v\d+\.\d+/)?(_ping|containers|images|networks|volumes|info|swarm)(/|$)", "docker_api"),
    (r"^/api/?$|^/api/v1/?$|^/apis(/|$)|^/api/v1/(namespaces|pods|nodes|secrets|configmaps|services)", "k8s_api"),
    (r"^/(v\d+\.\d+/)?version$|^/(healthz|livez|readyz)$", "orch_version"),
    (r"^/(robots\.txt|sitemap.*\.xml)$", "robots_sitemap"),
    (r"^/(server-status|server-info|phpinfo\.php|info\.php)", "server_status"),
    (r"^/api/v\d+/jobs/", "job_poll"),
    (r"^/api/(v\d+/)?(users|items|products|orders|customers|accounts)", "paged_items"),
]] + [(LOGIN_RE, "login")]

FALLBACK = {
    "ai_agent": [("debug_info", 3), ("env_file", 2), ("config_json", 2), ("k8s_api", 2), ("docker_api", 1), ("paged_items", 2), ("exec_shell", 1), ("sql_dump", 1)],
    "scanner": [("server_status", 2), ("actuator_env", 2), ("docker_api", 2), ("k8s_api", 1), ("git_config", 2), ("env_file", 1), ("debug_info", 1)],
    "bruteforce": [("login", 6), ("debug_info", 1)],
    "scraper": [("paged_items", 4), ("robots_sitemap", 2), ("job_poll", 1)],
    "probe": [("env_file", 2), ("config_json", 2), ("debug_info", 2), ("git_config", 1), ("actuator_env", 1)],
}


def classify(ua: str, path: str, method: str, st) -> str:
    """ua and path must already be lower-cased."""
    if any(s in ua for s in AI_SIGS): return "ai_agent"
    if any(s in ua for s in SCANNER_SIGS): return "scanner"
    if any(s in ua for s in BRUTE_SIGS) or (LOGIN_RE.search(path) and method != "GET") or st.login_attempts: return "bruteforce"
    if any(s in ua for s in SCRAPER_SIGS): return "scraper"
    return "probe"


def pick_vector(c) -> str:
    path = c.path.lower()
    for rx, name in ROUTES:
        if rx.search(path):
            return name
    table = list(FALLBACK.get(c.atype, FALLBACK["probe"]))
    if c.st.tarpit:   # floods are pulled into endless pagination / polling loops
        table += [("job_poll", 3 + c.st.tarpit), ("paged_items", 3 + c.st.tarpit)]
    names, weights = zip(*table)
    return c.r.choices(names, weights=weights, k=1)[0]
