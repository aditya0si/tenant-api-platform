"""End-to-end smoke test against the compose stack.

This runs the whole system as a deployed unit: a real binary on :8080, a real worker on :9090,
Postgres and Redis as containers, and a request path that crosses all of them.

Every assertion is about wiring the Go test suite cannot prove — that the image carries the right
entrypoints, that the containers resolve each other by service name, that migrations completed
before the API started, and that the security controls are active in the deployed binary rather
than only in tests.

It is worth committing because it found three real defects the suite did not: a blocked webhook
target answered 500 instead of 400, session responses carried no permissions, and the worker's
outbox-depth gauge did not exist while the queue was empty — which is precisely when nothing is
wrong and an alert on its absence would fire.

Note on webhook delivery: a full send round-trip is covered by internal/webhook's tests, which run
the guard in its loopback-permitting test form. It cannot be exercised here because the production
guard correctly refuses to deliver into private space, and every address a container can offer is
private. That refusal is the feature, not a gap in this script.
"""

import json
import urllib.error
import urllib.request
import uuid

API = "http://localhost:8080"
WORKER = "http://localhost:9090"
PASSWORD = "correct horse battery staple"

results = []


def req(method, path, body=None, token=None, key=None, base=API):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(base + path, data=data, method=method)
    if data is not None:
        r.add_header("Content-Type", "application/json")
    if token:
        r.add_header("Authorization", "Bearer " + token)
    if key:
        r.add_header("Idempotency-Key", key)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read()
            return resp.status, dict(resp.headers), (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else {}
        except Exception:
            parsed = {"_raw": raw[:200].decode(errors="replace")}
        return e.code, dict(e.headers), parsed


def hget(headers, name):
    """Case-insensitive header lookup.

    Go's net/http canonicalises header names — `X-Ratelimit-Limit`, not `X-RateLimit-Limit` — so
    an exact-match lookup silently returns None against a correct response. The first version of
    this script made that mistake and reported three passing checks as failures.
    """
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None


def scrape(base):
    with urllib.request.urlopen(base + "/metrics", timeout=10) as resp:
        return resp.read().decode()


def check(label, ok, detail=""):
    results.append((label, ok, detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  — {detail}" if detail else ""))


print("=== 1. probes ===")
for name, base in (("api", API), ("worker", WORKER)):
    try:
        s, _, b = req("GET", "/readyz", base=base)
        check(f"{name} /readyz is ready", s == 200 and b.get("status") == "ready", f"{s} {b}")
    except Exception as e:
        check(f"{name} /readyz reachable", False, str(e))

print("\n=== 2. a session survives the deployed path ===")
email = f"smoke-{uuid.uuid4().hex[:10]}@smoke.test"
s, _, b = req("POST", "/v1/auth/register",
              {"email": email, "password": PASSWORD, "tenant_name": "Smoke"})
if s == 429:
    check("register", False,
          "429 — PolicyRegister is 5/hour per address; flush the register buckets or wait")
    token = tenant = None
elif s == 201 and b.get("data", {}).get("access_token"):
    token = b["data"]["access_token"]
    tenant = b["data"]["tenants"][0]["tenant_id"]
    perms = b["data"]["tenants"][0].get("permissions") or []
    check("register returned a session", True, f"tenant {tenant}")
    check("session reports expires_in", b["data"].get("expires_in", 0) > 0,
          f"{b['data'].get('expires_in')}s")
    check("session tenant entry carries permissions", len(perms) > 0,
          f"{len(perms)} perms")
else:
    check("register returned a session", False, f"{s} {b}")
    token = tenant = None

if token:
    print("\n=== 3. identity and request correlation ===")
    s, h, b = req("GET", "/v1/me", token=token)
    check("/v1/me is 200", s == 200, f"{s}")
    check("/v1/me reports auth_method jwt", b.get("data", {}).get("auth_method") == "jwt")
    check("X-Request-Id echoed", bool(hget(h, "X-Request-Id")), str(hget(h, "X-Request-Id"))[:8])

    print("\n=== 4. the limiter is live and keyed on the tenant (proves Redis wiring) ===")
    s, h, _ = req("GET", f"/v1/tenants/{tenant}/projects", token=token)
    limit, remaining = hget(h, "X-Ratelimit-Limit"), hget(h, "X-Ratelimit-Remaining")
    check("authenticated limit advertised", limit is not None, f"limit={limit} remaining={remaining}")
    check("limiter is not degraded", hget(h, "X-Ratelimit-Degraded") is None,
          "X-Ratelimit-Degraded present")

    print("\n=== 5. writes are idempotent ===")
    key = f"smoke-{uuid.uuid4().hex[:8]}"
    payload = {"name": "Smoke project", "description": "created by the smoke test"}
    s1, h1, b1 = req("POST", f"/v1/tenants/{tenant}/projects", payload, token=token, key=key)
    check("create project is 201", s1 == 201, f"{s1}")
    check("Location names the resource", hget(h1, "Location") is not None,
          str(hget(h1, "Location"))[-12:])
    pid = b1.get("data", {}).get("id")

    s2, _, b2 = req("POST", f"/v1/tenants/{tenant}/projects", payload, token=token, key=key)
    check("a retry replays rather than duplicating",
          s2 == 201 and b2.get("data", {}).get("id") == pid, f"{s2}")

    s3, _, b3 = req("GET", f"/v1/tenants/{tenant}/projects", token=token)
    ids = [p["id"] for p in b3.get("data", [])]
    check("exactly one project exists after the retry", ids.count(pid) == 1, f"{len(ids)} project(s)")

    print("\n=== 6. the SSRF guard refuses, as a client error ===")
    for target, label in [
        ("http://169.254.169.254/latest/meta-data/", "cloud metadata"),
        ("http://10.0.0.1/internal", "RFC1918"),
        ("http://127.0.0.1:8080/healthz", "loopback"),
    ]:
        s, _, b = req("POST", f"/v1/tenants/{tenant}/webhooks",
                      {"url": target, "events": ["invoice.created"]},
                      token=token, key=f"smoke-wh-{uuid.uuid4().hex[:8]}")
        code = (b.get("error") or {}).get("code")
        msg = (b.get("error") or {}).get("message", "")
        check(f"{label} refused with 400", s == 400 and code == "validation_failed",
              f"status {s} code {code} — {msg[:52]}")

    print("\n=== 7. tenant boundaries ===")
    s, _, _ = req("GET", f"/v1/tenants/{uuid.uuid4()}/projects", token=token)
    check("unknown tenant is 404, never 403", s == 404, f"{s}")

    s, _, _ = req("GET", "/v1/me")
    check("no credential is 401", s == 401, f"{s}")

print("\n=== 8. metrics on both processes ===")
print("     (driving the login limit first, so the counter has a child to report)")
for _ in range(14):
    req("POST", "/v1/auth/login", {"email": "nobody@invalid.test", "password": "wrong"})

api_metrics = scrape(API)
for m in ["http_requests_total", "db_up", "ratelimit_limited_total"]:
    check(f"api /metrics exposes {m}", m in api_metrics)

worker_metrics = scrape(WORKER)
check("worker /metrics exposes webhook_outbox_depth", "webhook_outbox_depth" in worker_metrics)
for state in ("pending", "dead"):
    check(f"  depth reports {state} at zero when the outbox is empty",
          f'webhook_outbox_depth{{state="{state}"}}' in worker_metrics)

# webhook_delivery_attempts_total is deliberately NOT asserted here. It is a counter with no series
# until a delivery is attempted, and in a compose network no delivery can be attempted: every
# address a container can offer is private, and the production guard correctly refuses those. The
# first version of this script asserted its presence and reported a failure against correct code.
# The counter is covered in internal/webhook/worker_test.go, where the guard runs in its
# loopback-permitting test form and a delivery can actually happen.

print("\n=== SUMMARY ===")
passed = sum(1 for _, ok, _ in results if ok)
print(f"  {passed}/{len(results)} checks passed")
for label, ok, detail in results:
    if not ok:
        print(f"  FAILED: {label}  — {detail}")
raise SystemExit(0 if passed == len(results) else 1)
