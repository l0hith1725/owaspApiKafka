'use strict';

/**
 * Gateway Enforcement Integration Test
 *
 * Tests the full enforcement middleware in isolation — no real Kafka, no real Redis.
 * Uses in-memory mocks for ThreatStateStore and SecurityEventProducer.
 */

const express = require('express');
const request = require('supertest');
const { buildEnforcementMiddleware } = require('../../gateway/src/middleware/enforcement');

function makeMockThreatStore(threats = [], redisAvailable = true) {
  return {
    getThreatsForRequest: jest.fn(async () => ({ threats, redisAvailable })),
    failClosed: false,
  };
}

function makeMockProducer() {
  return {
    publishEvent: jest.fn(async () => {}),
  };
}

function buildApp(threatStore, producer, config = {}) {
  const app = express();
  app.set('trust proxy', true);
  app.use(express.json());

  const middleware = buildEnforcementMiddleware({
    threatStore,
    eventProducer: producer,
    config: { applicationId: 'test-app', gateway: { failClosed: false }, ...config },
  });

  app.use(middleware);
  app.get('/api/test', (req, res) => res.json({ ok: true }));
  app.post('/api/auth/login', (req, res) => res.status(401).json({ error: 'bad creds' }));
  return app;
}

describe('Gateway Enforcement Middleware', () => {
  test('allows request when no threats exist', async () => {
    const app = buildApp(makeMockThreatStore([]), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('blocks request when CRITICAL threat exists', async () => {
    const threats = [{
      riskScore: 90,
      riskLevel: 'CRITICAL',
      threatType: 'CREDENTIAL_STUFFING',
      recommendedAction: 'BLOCK',
      detectionId: 'det-1',
    }];
    const app = buildApp(makeMockThreatStore(threats), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/blocked/i);
  });

  test('rate limits request when HIGH threat exists', async () => {
    const threats = [{
      riskScore: 70,
      riskLevel: 'HIGH',
      threatType: 'BOLA',
      recommendedAction: 'RATE_LIMIT',
      detectionId: 'det-2',
    }];
    const app = buildApp(makeMockThreatStore(threats), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(429);
    expect(res.headers['retry-after']).toBeDefined();
  });

  test('warns but allows request when MEDIUM threat exists', async () => {
    const threats = [{
      riskScore: 40,
      riskLevel: 'MEDIUM',
      threatType: 'BOLA',
      recommendedAction: 'WARN',
      detectionId: 'det-3',
    }];
    const app = buildApp(makeMockThreatStore(threats), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(200);
    expect(res.headers['x-threat-warning']).toBe('BOLA');
  });

  test('fail-open when Redis is unavailable', async () => {
    const app = buildApp(makeMockThreatStore([], false), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(200); // Fail open
  });

  test('fail-closed blocks when Redis is unavailable and failClosed=true', async () => {
    const app = buildApp(
      makeMockThreatStore([], false),
      makeMockProducer(),
      { gateway: { failClosed: true } }
    );
    const res = await request(app).get('/api/test');
    expect(res.status).toBe(503);
  });

  test('publishes security event after successful request', async () => {
    const producer = makeMockProducer();
    const app = buildApp(makeMockThreatStore([]), producer);
    await request(app).get('/api/test');

    // Allow setImmediate to fire
    await new Promise(r => setImmediate(r));
    expect(producer.publishEvent).toHaveBeenCalledTimes(1);
  });

  test('sets x-request-id response header', async () => {
    const app = buildApp(makeMockThreatStore([]), makeMockProducer());
    const res = await request(app).get('/api/test');
    expect(res.headers['x-request-id']).toBeDefined();
  });

  test('respects incoming x-request-id header', async () => {
    const app = buildApp(makeMockThreatStore([]), makeMockProducer());
    const res = await request(app).get('/api/test').set('x-request-id', 'my-trace-id-123');
    expect(res.headers['x-request-id']).toBe('my-trace-id-123');
  });
});
