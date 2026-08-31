// Smoke-under-load test for the Envoy + scoring-service + coraza-service
// pipeline. Sends the same three traffic flavors generate-traffic.sh does
// (benign, bad-UA, CRS attack payloads) but concurrently, at ramping VUs, and
// asserts on latency + correctness rather than just printing what happened.
//
// Run: docker compose run --rm loadtest
// Tune: docker compose run --rm -e VUS=50 -e RAMP_DURATION=20s -e HOLD_DURATION=40s loadtest

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';
import { textSummary } from 'https://jslib.k6.io/k6-summary/0.0.2/index.js';

const BASE_URL = __ENV.BASE_URL || 'http://envoy:10000';
const VUS = Number(__ENV.VUS || 20);
const RAMP_DURATION = __ENV.RAMP_DURATION || '10s';
const HOLD_DURATION = __ENV.HOLD_DURATION || '20s';

const blockedLatency = new Trend('blocked_latency_ms');
const allowedLatency = new Trend('allowed_latency_ms');
const unexpected5xx = new Counter('unexpected_5xx');
// Strict correctness only for benign + bad-UA buckets — CRS-payload-only
// requests can legitimately land under the block threshold depending on
// current tuning (see scoring.py's CORAZA_SCORE_DIVISOR), so those are
// observed but not asserted on.
const expectedOutcomeRate = new Rate('expected_outcome_rate');

export const options = {
  stages: [
    { duration: RAMP_DURATION, target: VUS },
    { duration: HOLD_DURATION, target: VUS },
    { duration: '5s', target: 0 },
  ],
  thresholds: {
    http_req_duration: ['p(95)<500', 'p(99)<1000'],
    expected_outcome_rate: ['rate>0.98'],
    unexpected_5xx: ['count==0'],
  },
  // consistent percentile breakdown across every Trend, including our own
  // custom ones (allowed/blocked latency) — not just whatever a threshold
  // happens to reference.
  summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)'],
};

const NORMAL_UAS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)',
  'Mozilla/5.0 (X11; Linux x86_64)',
  'curl/8.1.0',
  'PostmanRuntime/7.36',
];
const MALICIOUS_UAS = ['sqlmap/1.7.2', 'nikto/2.5.0', 'nmap scripting engine', 'masscan/1.3'];
const PATHS = ['/', '/api/users', '/login', '/products/42', '/checkout', '/health', '/admin'];
const FAKE_IPS = ['203.0.113.10', '203.0.113.24', '198.51.100.7', '198.51.100.42', '192.0.2.15'];
const FAKE_DOMAINS = ['shop.example.com', 'api.example.com', 'admin.example.com'];
const CRS_PAYLOADS = [
  { method: 'GET', path: '/search', query: "id=1' OR '1'='1" },
  { method: 'POST', path: '/comment', body: 'comment=<script>alert(document.cookie)</script>', contentType: 'application/x-www-form-urlencoded' },
  { method: 'GET', path: '/files', query: 'path=../../../../etc/passwd' },
  { method: 'GET', path: '/ping', query: 'host=127.0.0.1;cat /etc/passwd' },
  { method: 'GET', path: '/proxy', query: 'url=file:///etc/passwd' },
];

function randOf(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function commonHeaders(ua) {
  return {
    'User-Agent': ua,
    'X-Forwarded-For': randOf(FAKE_IPS),
    Host: randOf(FAKE_DOMAINS),
  };
}

export default function () {
  const roll = Math.random();
  let res;
  let expectBlocked;
  let scoreStrictly = true;

  if (roll < 0.7) {
    // benign
    res = http.get(`${BASE_URL}${randOf(PATHS)}`, { headers: commonHeaders(randOf(NORMAL_UAS)) });
    expectBlocked = false;
  } else if (roll < 0.85) {
    // obviously bad User-Agent — the local heuristic alone scores this 0.95
    res = http.get(`${BASE_URL}${randOf(PATHS)}`, { headers: commonHeaders(randOf(MALICIOUS_UAS)) });
    expectBlocked = true;
  } else {
    // CRS attack payload with a normal UA
    scoreStrictly = false;
    const p = randOf(CRS_PAYLOADS);
    const url = p.query ? `${BASE_URL}${p.path}?${p.query}` : `${BASE_URL}${p.path}`;
    const headers = commonHeaders(randOf(NORMAL_UAS));
    if (p.body) {
      headers['Content-Type'] = p.contentType;
      res = http.post(url, p.body, { headers });
    } else {
      res = http.get(url, { headers });
    }
    expectBlocked = true;
  }

  const gotBlocked = res.status === 403;
  if (res.status >= 500) unexpected5xx.add(1);
  (gotBlocked ? blockedLatency : allowedLatency).add(res.timings.duration);
  if (scoreStrictly) expectedOutcomeRate.add(gotBlocked === expectBlocked);

  check(res, { 'no 5xx': (r) => r.status < 500 });

  sleep(Math.random() * 0.3);
}

let crsVersion = 'unknown';
try {
  crsVersion = open('/crs/VERSION').trim();
} catch (e) {
  // not mounted — fine, context just omits it
}

function buildContext() {
  return {
    target: BASE_URL,
    vus: VUS,
    rampDuration: RAMP_DURATION,
    holdDuration: HOLD_DURATION,
    crsVersion: crsVersion,
    runAt: new Date().toISOString(),
  };
}

export function setup() {
  const context = buildContext();
  console.log('=== SMOKE TEST CONTEXT ===');
  console.log(JSON.stringify(context, null, 2));
  console.log('==========================');
  return context;
}

export function handleSummary(data) {
  const context = buildContext();
  const contextBlock =
    `Target:        ${context.target}\n` +
    `VUs:           ${context.vus}\n` +
    `Ramp / Hold:   ${context.rampDuration} / ${context.holdDuration}\n` +
    `CRS version:   ${context.crsVersion}\n` +
    `Run at:        ${context.runAt}\n`;

  const stampedName = context.runAt.replace(/[:.]/g, '-');

  return {
    stdout: '\n=== TEST CONTEXT ===\n' + contextBlock + '\n' + textSummary(data, { indent: ' ', enableColors: true }) + '\n',
    [`/results/smoke-${stampedName}.json`]: JSON.stringify({ context, ...data }, null, 2),
    [`/results/smoke-${stampedName}.txt`]: '=== TEST CONTEXT ===\n' + contextBlock + '\n' + textSummary(data, { indent: ' ', enableColors: false }) + '\n',
  };
}
