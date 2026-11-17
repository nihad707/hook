"""Engine tests - stdlib only (no FastAPI / Redis / DB needed).

Run:  python -m unittest discover -t . -s tests -v
"""
import os
import sys
import unittest

os.environ.setdefault("HOOK_SECRET_KEY", "test-secret-key-0123456789abcdef")
os.environ.pop("REDIS_URL", None)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import classify, compute_delay, deceive, state_store  # noqa: E402
from engine.deception import FORBIDDEN_STATUSES  # noqa: E402
from engine.routing import FALLBACK, ROUTES, VECTORS  # noqa: E402
from engine.state import AttackState, MemoryStateStore, make_seed  # noqa: E402

SAMPLE_PATHS = ["/.env", "/.git/config", "/backup.sql", "/config.json", "/api/v2/internal/exec", "/debug", "/actuator/env",
                "/containers/json", "/images/json", "/info", "/_ping", "/api/v1/namespaces/production/secrets", "/api/v1/pods",
                "/version", "/robots.txt", "/sitemap.xml", "/server-status", "/api/v1/jobs/abc", "/api/users", "/wp-login.php",
                "/totally/unknown/path", "/"]


def fresh_state(ip="203.0.113.7", pid=1):
    return AttackState(pid, ip, make_seed(pid, ip), stage=1)


class EngineTests(unittest.TestCase):
    def test_every_vector_is_reachable_and_answers(self):
        names = {n for _, n in ROUTES} | {n for table in FALLBACK.values() for n, _ in table}
        self.assertTrue(names <= set(VECTORS))
        for path in SAMPLE_PATHS:
            for method in ("GET", "POST"):
                st = fresh_state()
                name, code, ctype, body = deceive(st, path, "cmd=id&page=3", method)
                self.assertIn(name, VECTORS)
                self.assertTrue(body, f"empty body for {path}")
                self.assertIsInstance(ctype, str)

    def test_deterministic_within_a_session(self):
        a = deceive(fresh_state(), "/.env", "", "GET")
        b = deceive(fresh_state(), "/.env", "", "GET")
        self.assertEqual(a, b)                                   # same attacker + path + stage -> same fake world
        other = deceive(fresh_state(ip="198.51.100.9"), "/.env", "", "GET")
        self.assertNotEqual(a[3], other[3])                      # another attacker gets another company

    def test_never_403_or_429_even_under_flood(self):
        store = MemoryStateStore()
        seen_levels, seen_codes = set(), set()
        for i in range(600):                                     # ~instant burst = flood
            st = store.touch(7, "198.51.100.200")
            kind = classify("python-requests/2.31", SAMPLE_PATHS[i % len(SAMPLE_PATHS)].lower(), "GET", st)
            st.atype = st.atype if st.atype and st.atype != "probe" else kind
            _, code, _, body = deceive(st, SAMPLE_PATHS[i % len(SAMPLE_PATHS)], "page=%d" % i, "GET")
            seen_levels.add(st.tarpit)
            seen_codes.add(code)
            self.assertNotIn(code, FORBIDDEN_STATUSES)
            self.assertTrue(body)
        self.assertGreater(max(seen_levels), 3, "flood must raise the tarpit level")
        self.assertTrue(seen_codes <= {200, 401})

    def test_tarpit_delay_grows_and_is_capped(self):
        from core.config import settings
        low = sum(compute_delay(0) for _ in range(50)) / 50
        mid = sum(compute_delay(4) for _ in range(50)) / 50
        high = max(compute_delay(12) for _ in range(50))
        self.assertLess(low, 200)
        self.assertGreater(mid, low + 500)
        self.assertLessEqual(high, settings.TARPIT_MAX_MS)

    def test_flood_decays_when_traffic_slows(self):
        store = MemoryStateStore()
        for _ in range(40):
            st = store.touch(1, "192.0.2.1")
        self.assertGreater(st.tarpit, 0)
        # simulate the window passing: wipe recorded hits, then a single request
        store._hits[(1, "192.0.2.1")].clear()
        st = store.touch(1, "192.0.2.1")
        self.assertLess(st.tarpit, 12)

    def test_login_lure_fails_then_wins_and_counters_persist(self):
        store = MemoryStateStore()
        codes = []
        for _ in range(40):
            st = store.touch(3, "203.0.113.50")
            st.atype = classify("hydra/9.5", "/login", "POST", st)
            _, code, _, _ = deceive(st, "/login", "", "POST")
            store.save(st)                                       # counters travel through save() like through Redis
            codes.append(code)
        self.assertIn(401, codes)
        self.assertIn(200, codes)
        self.assertGreater(codes.index(200), 4)                  # "wins" only after several failures

    def test_classification(self):
        st = fresh_state()
        self.assertEqual(classify("langchain/0.2", "/", "GET", st), "ai_agent")
        self.assertEqual(classify("nuclei/3.1", "/", "GET", st), "scanner")
        self.assertEqual(classify("hydra", "/", "GET", st), "bruteforce")
        self.assertEqual(classify("curl/8", "/", "GET", st), "scraper")
        self.assertEqual(classify("mozilla", "/wp-login.php", "POST", st), "bruteforce")
        self.assertEqual(classify("mozilla", "/", "GET", st), "probe")

    def test_state_facade_falls_back_to_memory_without_redis(self):
        st = state_store.touch(99, "10.9.9.9")
        self.assertEqual(st.stage, 1)
        self.assertTrue(st.is_new)
        st2 = state_store.touch(99, "10.9.9.9")
        self.assertEqual(st2.stage, 2)
        self.assertFalse(st2.is_new)
        self.assertEqual(st.seed, st2.seed)


if __name__ == "__main__":
    unittest.main()
