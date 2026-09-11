// k6 load test for tenant-api-platform.
//
// # What this measures
//
// The HTTP layer under concurrent authenticated traffic: achieved request rate, latency
// distribution, and error rate for the endpoints a client actually calls. It does not measure
// webhook delivery throughput — that is the worker's business and is bounded by the outbox — and it
// does not isolate the database.
//
// # Why the tenant count is what sets the achievable rate
//
// PolicyAPI bounds authenticated traffic at 600 requests per minute per tenant, which is 10 rps.
// That is a real production control (it exists so one tenant cannot starve the others) and it is
// deliberately not weakened for a benchmark: a load test that requires disabling a production
// control measures a system that is not the one deployed.
//
// So the rate is bought with tenants. TENANTS tenants, one VU each, each paced to just under its
// own 10 rps ceiling:
//
//	30 tenants x 7 rps = 210 rps aggregate, with each tenant at 70% of its limit
//
// The pacing margin matters. Running a tenant at its ceiling would make the run measure the
// limiter's rejection path rather than the endpoint.
//
// # Why seeding is a separate command
//
// PolicyRegister is 5 attempts per hour per address, so registering 30 tenants through the API is
// refused by the fourth. `cmd/loadseed` provisions them through the store instead — no HTTP, no
// limit involved.
//
// Reproduce:
//
//	docker compose up -d postgres redis
//	go run ./cmd/migrate up
//	go run ./cmd/api
//	go run ./cmd/loadseed -tenants 30 -out load/sessions.json
//	k6 run load/api.js
//
// Environment:
//
//	BASE_URL  default http://localhost:8080
//	TENANTS   must match what cmd/loadseed provisioned
//	SESSIONS  default sessions.json, resolved relative to THIS script

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Counter, Rate, Trend } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.4.0/index.js';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';

// The sessions cmd/loadseed wrote.
//
// Read here, at module scope, because k6 permits open() only in the init context — not inside
// setup(). The path is relative to THIS SCRIPT, not the working directory, so the bare default
// resolves to load/sessions.json. An absolute path via SESSIONS works too.
const SESSIONS_PATH = __ENV.SESSIONS || 'sessions.json';
const SESSIONS_RAW = open(SESSIONS_PATH);

// One VU per tenant. The mapping must stay injective: two VUs sharing a tenant would double that
// tenant's rate and push it into the limiter, which is the failure this configuration exists to
// avoid. scenarios below therefore set vus to exactly TENANTS.
const TENANTS = Number(__ENV.TENANTS || 30);

// Per-tenant pacing. 4 requests per iteration; at 7 rps that is one iteration every ~570ms.
//
// Kept clear of the 600/min (10 rps) ceiling — 7 rps is 70% of it. A 429 would mean the run is
// measuring the limiter and reporting its latency as the endpoint's, which is why the ceiling is
// not the pacing target. The margin also absorbs the small scheduling overhead Windows adds to
// every sleep(), which is what keeps the achieved rate slightly below the nominal one.
const TARGET_RPS_PER_TENANT = Number(__ENV.RPS_PER_TENANT || 7);
const REQUESTS_PER_READ_ITERATION = 4;
const READ_PACING_SECONDS = REQUESTS_PER_READ_ITERATION / TARGET_RPS_PER_TENANT;

// Writes run in their own window and at a lower rate, so their latency cannot contaminate the read
// numbers and so the two scenarios never draw on the same tenant's budget simultaneously.
const WRITE_VUS = Math.max(4, Math.floor(TENANTS / 4));
const WRITE_PACING_SECONDS = 0.25;

// Custom metrics, so a regression is attributable. The default k6 summary reports
// http_req_duration across every request, which would blend a fast project listing with a slower
// insert and hide which one moved.
const projectListDuration = new Trend('project_list_duration', true);
const projectCreateDuration = new Trend('project_create_duration', true);
const invoiceListDuration = new Trend('invoice_list_duration', true);
const apiKeyListDuration = new Trend('api_key_list_duration', true);
const meDuration = new Trend('me_duration', true);
const readErrors = new Rate('read_errors');
const writeErrors = new Rate('write_errors');

// readRequests counts requests issued by the read scenario, so the "did we actually reach the
// target volume" assertion can be a count rather than a rate.
//
// Asserting on http_reqs.rate would be wrong here: its rate is computed over the whole test window,
// which spans the read window AND the write window that follows at a lower rate. A correct run that
// hit its target during the reads would still fail, because the average over both windows is lower
// than the read-only rate. A count has no such ambiguity — 4 requests per iteration, so the count
// divided by the read window is the achieved rate exactly.
const readRequests = new Counter('read_requests');

export const options = {
  scenarios: {
    reads: {
      executor: 'constant-vus',
      vus: TENANTS,
      duration: '30s',
      exec: 'readPath',
      tags: { scenario: 'reads' },
    },
    writes: {
      executor: 'constant-vus',
      vus: WRITE_VUS,
      duration: '20s',
      exec: 'writePath',
      // After the read window closes, so the two never compete for one tenant's 600/min budget.
      startTime: '32s',
      tags: { scenario: 'writes' },
    },
  },
  thresholds: {
    // DESIGN.md asserts these targets; stating them as thresholds makes the run fail loudly instead
    // of requiring someone to read a summary and decide whether it passed.
    'http_req_duration{scenario:reads}': ['p(95)<150'],
    'http_req_duration{scenario:writes}': ['p(95)<250'],
    'read_errors': ['rate<0.01'],
    'write_errors': ['rate<0.01'],
    'http_req_failed': ['rate<0.01'],
    // The achieved volume is asserted, not assumed: without this, a run where every request was
    // fast because very few arrived would pass and report a target it never reached.
    //
    // 4500 read requests over the 30s read window is 150 rps, against a 210 rps target — a floor
    // rather than the target, so Windows scheduling jitter cannot fail a fundamentally healthy run
    // while still catching one that stalled. The measured run produced 5912.
    'read_requests': ['count>4500'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

// setup validates the sessions cmd/loadseed wrote.
//
// It reads the module-scope value rather than opening the file itself: k6 restricts open() to the
// init context and throws if it is called from setup(). The first version of this script made that
// mistake, which is the kind of defect that only appears when a benchmark is executed rather than
// reviewed.
export function setup() {
  let sessions;
  try {
    sessions = JSON.parse(SESSIONS_RAW);
  } catch (e) {
    throw new Error(`${SESSIONS_PATH} is not valid JSON (${e}); re-run cmd/loadseed`);
  }

  if (!Array.isArray(sessions) || sessions.length === 0) {
    throw new Error(`${SESSIONS_PATH} contains no sessions; re-run cmd/loadseed`);
  }
  if (sessions.length < TENANTS) {
    // Loud rather than silently reduced. With fewer sessions than VUs, two VUs would share a tenant
    // and the run would report a throughput its configuration never produced.
    throw new Error(
      `${SESSIONS_PATH} holds ${sessions.length} sessions but TENANTS is ${TENANTS}. Re-run ` +
      `loadseed with -tenants ${TENANTS}, or set TENANTS=${sessions.length}.`,
    );
  }
  for (const s of sessions) {
    if (!s.token || !s.tenantID) {
      throw new Error(`${SESSIONS_PATH} has a session missing token or tenantID`);
    }
  }

  return { sessions };
}

function sessionFor(data) {
  // __VU is 1-based. The modulo keeps a VU bound to one tenant; vus === TENANTS makes it injective.
  return data.sessions[(__VU - 1) % data.sessions.length];
}

function authHeaders(session) {
  return { headers: { Authorization: `Bearer ${session.token}` } };
}

// readPath is the no-write path: the endpoints a dashboard hits repeatedly.
export function readPath(data) {
  const session = sessionFor(data);

  const me = http.get(`${BASE_URL}/v1/me`, authHeaders(session));
  meDuration.add(me.timings.duration);
  readErrors.add(me.status !== 200);
  check(me, { 'me is 200': (r) => r.status === 200 });

  const projects = http.get(`${BASE_URL}/v1/tenants/${session.tenantID}/projects`, authHeaders(session));
  projectListDuration.add(projects.timings.duration);
  readErrors.add(projects.status !== 200);
  check(projects, {
    'project listing is 200': (r) => r.status === 200,
    'project listing is wrapped in data': (r) => {
      try { return r.json().data !== undefined; } catch (e) { return false; }
    },
  });

  const invoices = http.get(`${BASE_URL}/v1/tenants/${session.tenantID}/invoices`, authHeaders(session));
  invoiceListDuration.add(invoices.timings.duration);
  readErrors.add(invoices.status !== 200);
  check(invoices, { 'invoice listing is 200': (r) => r.status === 200 });

  const keys = http.get(`${BASE_URL}/v1/tenants/${session.tenantID}/api-keys`, authHeaders(session));
  apiKeyListDuration.add(keys.timings.duration);
  readErrors.add(keys.status !== 200);
  check(keys, { 'api-key listing is 200': (r) => r.status === 200 });

  // One add for the four requests above. The counter is about achieved volume; whether those
  // requests succeeded is what read_errors measures.
  readRequests.add(REQUESTS_PER_READ_ITERATION);

  // The pacing that keeps this tenant under its 600/min ceiling.
  sleep(READ_PACING_SECONDS);
}

// writePath is the mutating path, in its own window.
export function writePath(data) {
  const session = sessionFor(data);

  // A fresh key per request, so every call is a genuine first execution. Reusing one would exercise
  // the replay path and report the idempotency store's read latency instead of a real insert.
  const key = `load-${__VU}-${__ITER}-${randomString(8)}`;

  const created = http.post(
    `${BASE_URL}/v1/tenants/${session.tenantID}/projects`,
    JSON.stringify({
      name: `Load project ${__VU}-${__ITER}`,
      description: 'created by the load test',
    }),
    {
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${session.token}`,
        'Idempotency-Key': key,
      },
    },
  );
  projectCreateDuration.add(created.timings.duration);
  writeErrors.add(created.status !== 201);
  check(created, { 'project create is 201': (r) => r.status === 201 });

  sleep(WRITE_PACING_SECONDS);
}

// handleSummary writes a machine-readable result and prints the numbers it quotes.
export function handleSummary(data) {
  // setup_data is everything setup() returned — every tenant's access token, in full.
  //
  // They expire with AccessTokenTTL, but this artifact is committed beside the numbers it records,
  // and a file in a repository must not contain credentials however short-lived. Deleting them here
  // rather than scrubbing the file afterwards is the difference between a tool whose output is safe
  // by construction and one that is safe as long as somebody remembers to clean up.
  delete data.setup_data;

  return {
    'load/results.json': JSON.stringify(data, null, 2),
    stdout: textSummary(data),
  };
}

// textSummary prints the numbers the README quotes, so the run's own output is their source rather
// than a hand-copy of a console scroll.
function textSummary(data) {
  const m = data.metrics;
  const fmt = (n) => (n === undefined ? '-' : `${n.toFixed(2)}ms`);
  const line = (label, metric) => {
    if (!metric || !metric.values) return `${label}: (not measured)`;
    const v = metric.values;
    return `${label}: avg ${fmt(v.avg)}  p90 ${fmt(v['p(90)'])}  p95 ${fmt(v['p(95)'])}  p99 ${fmt(v['p(99)'])}  max ${fmt(v.max)}`;
  };
  const errRate = (name) => {
    const metric = m[name];
    if (!metric || !metric.values) return `${name}: (not measured)`;
    return `${name}: ${(metric.values.rate * 100).toFixed(3)}%`;
  };

  return [
    '',
    '=== tenant-api-platform load test ===',
    line('all requests       ', m.http_req_duration),
    line('project listing    ', m.project_list_duration),
    line('project create     ', m.project_create_duration),
    line('invoice listing    ', m.invoice_list_duration),
    line('api-key listing    ', m.api_key_list_duration),
    line('/v1/me             ', m.me_duration),
    '',
    `requests: ${m.http_reqs ? m.http_reqs.values.count : '-'}  ` +
      `rate: ${m.http_reqs ? m.http_reqs.values.rate.toFixed(1) : '-'}/s (whole run)`,
    `read requests: ${m.read_requests ? m.read_requests.values.count : '-'} over the 30s read window ` +
      `= ${m.read_requests ? (m.read_requests.values.count / 30).toFixed(1) : '-'}/s`,
    errRate('read_errors'),
    errRate('write_errors'),
    `http_req_failed: ${m.http_req_failed ? (m.http_req_failed.values.rate * 100).toFixed(3) : '-'}%`,
    '',
  ].join('\n');
}
