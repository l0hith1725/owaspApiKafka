#!/usr/bin/env node
'use strict';

/**
 * Normal User Simulation — should produce NO threat signals.
 *
 * Demonstrates that the platform does not produce false positives
 * for legitimate, low-frequency usage patterns.
 */

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function run() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  NORMAL USER SIMULATION (false-positive check)');
  console.log(`  Target: ${GATEWAY_URL}`);
  console.log('═══════════════════════════════════════════════════════\n');

  // 1. Successful login
  let res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
  });
  const { token } = await res.json();
  console.log(`Login: HTTP ${res.status} ${res.status === 200 ? '✓' : '✗'}`);

  // 2. Browse own orders
  for (let i = 1; i <= 3; i++) {
    await delay(500);
    res = await fetch(`${GATEWAY_URL}/api/orders/${i}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    console.log(`GET /api/orders/${i}: HTTP ${res.status} ${res.status < 400 ? '✓' : '–'}`);
  }

  // 3. One failed login attempt (mistyped password)
  await delay(1000);
  res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.com', password: 'typo' }),
  });
  console.log(`Failed login (typo): HTTP ${res.status} ${res.status === 401 ? '✓ (expected 401)' : '!'}`);

  // 4. Correct login again
  await delay(1000);
  res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'alice@example.com', password: 'password123' }),
  });
  console.log(`Re-login: HTTP ${res.status} ${res.status === 200 ? '✓' : '✗'}`);

  console.log('\n✅ Normal user simulation complete — no blocks expected');
  console.log('   (Check Redis: redis-cli keys "threat:*" — should be empty)');
}

run().catch(err => { console.error(err.message); process.exit(1); });
