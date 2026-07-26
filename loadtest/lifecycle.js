// SIGIMORA Load Test — Full Lifecycle
// Usage: k6 run lifecycle.js
//
// Exercises: create network → DKG → sign → verify → trace
// Replace BASE_URL and API_KEY below.

import { check, sleep } from 'k6';
import http from 'k6/http';

const BASE_URL = __ENV.BASE_URL || 'http://127.0.0.1:8080';
const API_KEY  = __ENV.API_KEY  || 'sigimora_Test200StatusKey0000000';

const HEADERS = {
  'Content-Type': 'application/json',
  Authorization: `Bearer ${API_KEY}`,
};

export const options = {
  vus: 1,
  iterations: 5,
  thresholds: {
    http_req_duration: ['p(95)<2000'],
    http_req_failed: ['rate<0.05'],
  },
};

export default function () {
  // 1. Health
  let r = http.get(`${BASE_URL}/api/v1/health`, { headers: HEADERS });
  check(r, { 'health status is ok': (res) => res.json('status') === 'ok' });

  // 2. Create network
  r = http.post(`${BASE_URL}/api/v1/networks`, JSON.stringify({ n: 4, t: 2 }), { headers: HEADERS });
  check(r, { 'network created': (res) => res.status === 200 });
  const netId = r.json('network.id');
  const trackingSk = r.json('tracking_secret_key_hex');

  // 3. Run DKG
  r = http.post(`${BASE_URL}/api/v1/networks/${netId}/dkg`, '{}', { headers: HEADERS });
  check(r, { 'dkg completed': (res) => res.status === 200 });

  // 4. Sign a message
  const quorum = [1, 2, 3];
  const msgHex = 'deadbeefcafebabe';
  r = http.post(
    `${BASE_URL}/api/v1/networks/${netId}/sign`,
    JSON.stringify({ message: msgHex, quorum }),
    { headers: HEADERS },
  );
  check(r, { 'sign succeeded': (res) => res.status === 200 });
  const sigHex = r.json('combined_sig_hex');

  // 5. Verify signature
  r = http.post(
    `${BASE_URL}/api/v1/networks/${netId}/verify`,
    JSON.stringify({ message: msgHex, signature_hex: sigHex, quorum }),
    { headers: HEADERS },
  );
  check(r, { 'verify succeeded': (res) => res.json('valid') === true });

  // 6. Trace signers (if tracking key available)
  const txId = r.json('tx_id') || '';
  if (trackingSk) {
    r = http.post(
      `${BASE_URL}/api/v1/networks/${netId}/trace`,
      JSON.stringify({ tx_id: txId, tracking_key_hex: trackingSk }),
      { headers: HEADERS },
    );
    check(r, { 'trace succeeded': (res) => res.status === 200 });
  }

  sleep(1);
}
