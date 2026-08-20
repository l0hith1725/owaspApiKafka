'use strict';

const { CredentialStuffingAnalyzer } = require('../../analyzers/src/analyzers/CredentialStuffingAnalyzer');

// Mock Redis with in-memory sorted sets
function makeMockRedis() {
  const store = {};
  return {
    eval: jest.fn(async (script, numKeys, key, now, windowMs, member, ttl) => {
      if (!store[key]) store[key] = new Map();
      const cutoff = now - windowMs;
      for (const [m, score] of store[key]) {
        if (score < cutoff) store[key].delete(m);
      }
      store[key].set(member, now);
      return store[key].size;
    }),
    zadd: jest.fn(async (key, score, member) => {
      if (!store[key]) store[key] = new Map();
      store[key].set(member, score);
      return 1;
    }),
    zremrangebyscore: jest.fn(async () => 0),
    zcard: jest.fn(async (key) => store[key]?.size || 0),
    ping: jest.fn(async () => 'PONG'),
    _store: store,
  };
}

function makeEvent(overrides = {}) {
  return {
    requestId: `req-${Math.random().toString(36).slice(2)}`,
    applicationId: 'test-app',
    timestamp: new Date().toISOString(),
    sourceIp: '1.2.3.4',
    httpMethod: 'POST',
    path: '/api/auth/login',
    endpointId: 'POST:/api/auth/login',
    statusCode: 401,
    userId: null,
    authSuccess: false,
    userAgent: 'test-agent',
    metadata: {},
    ...overrides,
  };
}

describe('CredentialStuffingAnalyzer', () => {
  let redis;
  let analyzer;

  beforeEach(() => {
    redis = makeMockRedis();
    analyzer = new CredentialStuffingAnalyzer(
      {
        applicationId: 'test-app',
        windowSeconds: 60,
        maxIpFailures: 5,
        maxUserFailures: 3,
        maxDistinctAccounts: 4,
        maxDistinctIps: 3,
        enabled: true,
      },
      { redis }
    );
  });

  test('returns no threat for non-auth endpoints', async () => {
    const event = makeEvent({ endpointId: 'GET:/api/orders/1', statusCode: 200 });
    const result = await analyzer.analyze(event);
    expect(result.threatDetected).toBe(false);
    expect(result.riskScore).toBe(0);
  });

  test('returns no threat for successful auth', async () => {
    const event = makeEvent({ statusCode: 200, authSuccess: true });
    const result = await analyzer.analyze(event);
    expect(result.threatDetected).toBe(false);
  });

  test('detects IP-based credential stuffing after threshold', async () => {
    const ip = '10.0.0.1';
    let result;
    for (let i = 0; i < 6; i++) {
      result = await analyzer.analyze(makeEvent({ sourceIp: ip }));
    }
    expect(result.threatDetected).toBe(true);
    expect(result.riskScore).toBeGreaterThanOrEqual(30);
    expect(result.contributions.some(c => c.analyzerId === 'cs:ip-failures')).toBe(true);
  });

  test('detects account-targeted attack after threshold', async () => {
    const userId = 'victim-user';
    let result;
    for (let i = 0; i < 4; i++) {
      result = await analyzer.analyze(makeEvent({
        userId,
        metadata: { targetUserId: userId },
      }));
    }
    expect(result.threatDetected).toBe(true);
    expect(result.contributions.some(c => c.analyzerId === 'cs:user-failures')).toBe(true);
  });

  test('is disabled when enabled=false', async () => {
    const disabledAnalyzer = new CredentialStuffingAnalyzer(
      { applicationId: 'test-app', enabled: false },
      { redis }
    );
    const result = await disabledAnalyzer.analyze(makeEvent());
    expect(result.threatDetected).toBe(false);
  });

  test('risk score does not exceed 100', async () => {
    const ip = '99.99.99.99';
    let result;
    for (let i = 0; i < 50; i++) {
      result = await analyzer.analyze(makeEvent({ sourceIp: ip }));
    }
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });
});
