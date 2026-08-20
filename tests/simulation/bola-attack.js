#!/usr/bin/env node
'use strict';

/**
 * BOLA (Broken Object Level Authorization) Attack Simulation
 *
 * Simulates an attacker systematically accessing order IDs they don't own.
 *
 * Expected behavior:
 *   - First requests pass (below threshold)
 *   - After accessing many distinct resource IDs, analyzer flags the user
 *   - Threat written to Redis; subsequent requests blocked
 */

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const DELAY_MS    = parseInt(process.env.DELAY_MS || '100');

async function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

async function login(email, password) {
  const res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  const body = await res.json();
  return body.token;
}

async function getOrder(token, orderId, attempt) {
  const res = await fetch(`${GATEWAY_URL}/api/orders/${orderId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const status = res.status;
  const blocked = status === 403;
  console.log(`[${attempt.toString().padStart(3)}] GET /api/orders/${orderId} → HTTP ${status}${blocked ? ' ⛔ BLOCKED' : ' ✓'}`);
  return { status, blocked };
}

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  BOLA ATTACK SIMULATION');
  console.log(`  Target: ${GATEWAY_URL}`);
  console.log('═══════════════════════════════════════════════════════\n');

  // Login as a legitimate user
  console.log('Authenticating as bob@example.com...');
  const token = await login('bob@example.com', 'pass456');
  if (!token) { console.error('Login failed'); process.exit(1); }
  console.log('Authenticated ✓\n');

  console.log('Starting resource enumeration (BOLA attack)...\n');

  let blocked = 0;
  let passed  = 0;

  for (let i = 1; i <= 30; i++) {
    const result = await getOrder(token, i, i);
    if (result.blocked) blocked++;
    else passed++;
    await delay(DELAY_MS);
  }

  console.log('\n═══════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${passed} passed | ${blocked} blocked`);
  console.log('═══════════════════════════════════════════════════════');
}

main().catch(err => { console.error(err.message); process.exit(1); });
