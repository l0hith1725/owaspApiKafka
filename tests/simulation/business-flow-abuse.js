#!/usr/bin/env node
'use strict';

/**
 * Business Flow Abuse Simulation
 *
 * Simulates an attacker rapidly completing the payment flow multiple times,
 * which should trigger the BusinessFlowAbuseAnalyzer.
 */

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const DELAY_MS = parseInt(process.env.DELAY_MS || '300');

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function post(url, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function patch(url, body, token) {
  const res = await fetch(url, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}

async function completePaymentFlow(iteration) {
  console.log(`\n── Flow iteration ${iteration} ─────────────────────────`);

  // Step 1: Login
  let r = await post(`${GATEWAY_URL}/api/auth/login`, { email: 'alice@example.com', password: 'password123' });
  console.log(`  POST /api/auth/login       → ${r.status}`);
  if (r.status === 403) { console.log('  ⛔ BLOCKED at login'); return false; }
  const token = r.body.token;

  await delay(DELAY_MS);

  // Step 2: Add payment method
  r = await post(`${GATEWAY_URL}/api/payment-methods`, { cardLast4: '4242', cardType: 'visa' }, token);
  console.log(`  POST /api/payment-methods  → ${r.status}`);
  if (r.status === 403) { console.log('  ⛔ BLOCKED'); return false; }

  await delay(DELAY_MS);

  // Step 3: Update account
  r = await patch(`${GATEWAY_URL}/api/account`, { address: '123 Hacker St' }, token);
  console.log(`  PATCH /api/account         → ${r.status}`);
  if (r.status === 403) { console.log('  ⛔ BLOCKED'); return false; }

  await delay(DELAY_MS);

  // Step 4: Transfer money
  r = await post(`${GATEWAY_URL}/api/transfers`, { toUserId: 'user-2', amount: 10 }, token);
  console.log(`  POST /api/transfers        → ${r.status}`);
  if (r.status === 403) { console.log('  ⛔ BLOCKED'); return false; }

  console.log('  ✓ Flow completed');
  return true;
}

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  BUSINESS FLOW ABUSE SIMULATION (Payment Flow)');
  console.log(`  Target: ${GATEWAY_URL}`);
  console.log('═══════════════════════════════════════════════════════');

  let completed = 0;
  let blocked   = 0;

  for (let i = 1; i <= 5; i++) {
    const ok = await completePaymentFlow(i);
    if (ok) completed++;
    else { blocked++; break; }
    await delay(500);
  }

  console.log('\n═══════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${completed} flows completed | ${blocked} blocked`);
  console.log('═══════════════════════════════════════════════════════');
}

main().catch(err => { console.error(err.message); process.exit(1); });
