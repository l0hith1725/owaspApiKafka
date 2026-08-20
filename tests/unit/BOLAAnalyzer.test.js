'use strict';

const { BOLAAnalyzer } = require('../../analyzers/src/analyzers/BOLAAnalyzer');

function makeMockRedis() {
  const store = {};
  return {
    eval: jest.fn(async (script, numKeys, key, now, windowMs, member, ttl) => {
      if (!store[key]) store[key] = new Map();
      const cutoff = now - windowMs;
      for (const [m, score] of store[key]) { if (score < cutoff) store[key].delete(m); }
      store[key].set(member, now);
      return store[key].size;
    }),
    zadd: jest.fn(async (key, score, member) => {
      if (!store[key]) store[key] = new Map();
      store[key].set(member, score);
    }),
    zremrangebyscore: jest.fn(async () => 0),
    zcard: jest.fn(async (key) => store[key]?.size || 0),
  };
}

function makeOrderEvent(userId, orderId, ownerId = null) {
  return {
    requestId: `req-${Math.random().toString(36).slice(2)}`,
    applicationId: 'test-app',
    timestamp: new Date().toISOString(),
    sourceIp: '5.5.5.5',
    httpMethod: 'GET',
    path: `/api/orders/${orderId}`,
    endpointId: `GET:/api/orders/${orderId}`,
    statusCode: 200,
    userId,
    authenticationType: 'JWT',
    authSuccess: true,
    resourceType: 'order',
    resourceId: String(orderId),
    action: 'READ',
    metadata: ownerId ? { ownerUserId: ownerId } : {},
  };
}

describe('BOLAAnalyzer', () => {
  let redis;
  let analyzer;

  beforeEach(() => {
    redis = makeMockRedis();
    analyzer = new BOLAAnalyzer(
      {
        applicationId: 'test-app',
        windowSeconds: 120,
        maxDistinctResources: 10,
        maxCrossOwnershipAccess: 2,
        enabled: true,
      },
      { redis }
    );
  });

  test('no threat for unauthenticated request', async () => {
    const event = { ...makeOrderEvent(null, 1), userId: null };
    const result = await analyzer.analyze(event);
    expect(result.threatDetected).toBe(false);
  });

  test('no threat for WRITE operations', async () => {
    const event = { ...makeOrderEvent('user-1', 1), action: 'WRITE' };
    const result = await analyzer.analyze(event);
    expect(result.threatDetected).toBe(false);
  });

  test('detects resource enumeration after threshold', async () => {
    let result;
    for (let i = 1; i <= 12; i++) {
      result = await analyzer.analyze(makeOrderEvent('user-attacker', i));
    }
    expect(result.threatDetected).toBe(true);
    expect(result.contributions.some(c => c.analyzerId === 'bola:resource-enumeration')).toBe(true);
  });

  test('detects cross-ownership access', async () => {
    let result;
    for (let i = 1; i <= 3; i++) {
      result = await analyzer.analyze(makeOrderEvent('user-attacker', i, 'user-victim'));
    }
    expect(result.threatDetected).toBe(true);
    expect(result.contributions.some(c => c.analyzerId === 'bola:cross-ownership')).toBe(true);
  });

  test('no cross-ownership flag when user owns the resource', async () => {
    let result;
    for (let i = 1; i <= 5; i++) {
      result = await analyzer.analyze(makeOrderEvent('user-1', i, 'user-1'));
    }
    // May flag enumeration but NOT cross-ownership
    const crossOwnerContrib = result.contributions.find(c => c.analyzerId === 'bola:cross-ownership');
    expect(crossOwnerContrib).toBeUndefined();
  });

  test('disabled analyzer returns no threat', async () => {
    const disabled = new BOLAAnalyzer({ applicationId: 'test-app', enabled: false }, { redis });
    const result = await disabled.analyze(makeOrderEvent('user-1', 1));
    expect(result.threatDetected).toBe(false);
  });
});
