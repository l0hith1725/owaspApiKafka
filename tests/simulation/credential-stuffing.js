#!/usr/bin/env node
'use strict';

/**
 * Credential Stuffing Attack Simulation
 *
 * Simulates an attacker trying many username/password combinations
 * against the login endpoint from a single IP.
 *
 * Expected behavior:
 *   - First N requests pass (analyzer needs time to detect)
 *   - Analyzer detects pattern, writes threat to Redis
 *   - Subsequent requests blocked by gateway (403)
 *
 * Usage: node tests/simulation/credential-stuffing.js
 */

const GATEWAY_URL = process.env.GATEWAY_URL || 'http://localhost:3000';
const DELAY_MS    = parseInt(process.env.DELAY_MS || '200');
const COUNT       = parseInt(process.env.COUNT || '25');

const accounts = [
  { email: 'victim1@example.com', password: 'wrong1' },
  { email: 'victim2@example.com', password: 'wrong2' },
  { email: 'victim3@example.com', password: 'wrong3' },
  { email: 'victim4@example.com', password: 'wrong4' },
  { email: 'alice@example.com',   password: 'wrongpass' },
  { email: 'bob@example.com',     password: 'wrongpass' },
];

async function delay(ms) {
  return new Promise(r => setTimeout(r, ms));
}

async function attemptLogin(email, password, attempt) {
  const res = await fetch(`${GATEWAY_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });

  const status = res.status;
  const body = await res.json().catch(() => ({}));
  const blocked = status === 403;
  const rateLimited = status === 429;

  console.log(`[${attempt.toString().padStart(3)}] ${email} → HTTP ${status}${blocked ? ' ⛔ BLOCKED' : rateLimited ? ' 🔴 RATE LIMITED' : ' ✓'}`);
  return { status, blocked, rateLimited };
}

async function main() {
  console.log('═══════════════════════════════════════════════════════');
  console.log('  CREDENTIAL STUFFING ATTACK SIMULATION');
  console.log(`  Target: ${GATEWAY_URL}`);
  console.log(`  Attempts: ${COUNT} | Delay: ${DELAY_MS}ms`);
  console.log('═══════════════════════════════════════════════════════\n');

  let blocked = 0;
  let rateLimited = 0;
  let passed = 0;

  for (let i = 1; i <= COUNT; i++) {
    const cred = accounts[i % accounts.length];
    const result = await attemptLogin(cred.email, cred.password, i);

    if (result.blocked) blocked++;
    else if (result.rateLimited) rateLimited++;
    else passed++;

    await delay(DELAY_MS);
  }

  console.log('\n═══════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${passed} passed | ${rateLimited} rate-limited | ${blocked} blocked`);
  console.log('═══════════════════════════════════════════════════════');
  console.log('\n✅ Check Kafka UI (http://localhost:8080) for security events');
  console.log('✅ Check Redis: redis-cli keys "threat:*"');
}

main().catch(err => {
  console.error('Simulation failed:', err.message);
  process.exit(1);
});
