'use strict';

const { ThreatStateStore } = require('../../common/src/services/ThreatStateStore');

function makeMockRedis(failOn = null) {
  const store = {};
  return {
    set: jest.fn(async (key, value, ex, ttl) => {
      if (failOn === 'set') throw new Error('Redis set failed');
      store[key] = { value, ttl };
      return 'OK';
    }),
    get: jest.fn(async (key) => store[key]?.value || null),
    del: jest.fn(async (key) => { delete store[key]; return 1; }),
    pipeline: jest.fn(() => ({
      get: jest.fn(function(key) { this._keys = this._keys || []; this._keys.push(key); return this; }),
      exec: jest.fn(async function() {
        if (failOn === 'pipeline') throw new Error('Redis pipeline failed');
        return (this._keys || []).map(k => [null, store[k]?.value || null]);
      }),
    })),
    ping: jest.fn(async () => {
      if (failOn === 'ping') throw new Error('connection refused');
      return 'PONG';
    }),
    _store: store,
  };
}

describe('ThreatStateStore', () => {
  test('setThreat writes to Redis with correct key format', async () => {
    const redis = makeMockRedis();
    const store = new ThreatStateStore(redis);

    await store.setThreat({
      applicationId: 'my-app',
      dimension: 'ip',
      value: '1.2.3.4',
      threatData: { threatType: 'CREDENTIAL_STUFFING', riskScore: 85, recommendedAction: 'BLOCK' },
      ttlSeconds: 300,
    });

    expect(redis.set).toHaveBeenCalledWith(
      'threat:my-app:ip:1.2.3.4',
      expect.any(String),
      'EX',
      300,
    );

    const written = JSON.parse(redis.set.mock.calls[0][1]);
    expect(written.threatType).toBe('CREDENTIAL_STUFFING');
    expect(written.createdAt).toBeDefined();
    expect(written.expiresAt).toBeDefined();
  });

  test('getThreatsForRequest returns threats sorted by riskScore', async () => {
    const redis = makeMockRedis();
    const store = new ThreatStateStore(redis);

    await store.setThreat({ applicationId: 'app', dimension: 'ip',   value: '1.2.3.4', threatData: { riskScore: 60, threatType: 'BOLA', recommendedAction: 'RATE_LIMIT' }, ttlSeconds: 300 });
    await store.setThreat({ applicationId: 'app', dimension: 'user', value: 'user-1',  threatData: { riskScore: 90, threatType: 'CREDENTIAL_STUFFING', recommendedAction: 'BLOCK' }, ttlSeconds: 300 });

    const { threats } = await store.getThreatsForRequest({
      applicationId: 'app',
      sourceIp: '1.2.3.4',
      userId: 'user-1',
    });

    expect(threats.length).toBe(2);
    expect(threats[0].riskScore).toBeGreaterThanOrEqual(threats[1].riskScore);
    expect(threats[0].threatType).toBe('CREDENTIAL_STUFFING');
  });

  test('getThreatsForRequest returns empty array when no threats', async () => {
    const redis = makeMockRedis();
    const store = new ThreatStateStore(redis);
    const { threats } = await store.getThreatsForRequest({ applicationId: 'app', sourceIp: '9.9.9.9' });
    expect(threats).toHaveLength(0);
  });

  test('getThreatsForRequest fails gracefully when Redis is down', async () => {
    const redis = makeMockRedis('pipeline');
    const store = new ThreatStateStore(redis);
    const { threats, redisAvailable } = await store.getThreatsForRequest({ applicationId: 'app', sourceIp: '1.1.1.1' });
    expect(threats).toHaveLength(0);
    expect(redisAvailable).toBe(false);
  });

  test('setThreat does not throw when Redis set fails', async () => {
    const redis = makeMockRedis('set');
    const store = new ThreatStateStore(redis);
    await expect(store.setThreat({
      applicationId: 'app', dimension: 'ip', value: '1.2.3.4',
      threatData: { riskScore: 90 }, ttlSeconds: 300,
    })).resolves.not.toThrow();
  });

  test('clearThreat removes the key', async () => {
    const redis = makeMockRedis();
    const store = new ThreatStateStore(redis);
    await store.setThreat({ applicationId: 'app', dimension: 'ip', value: '1.1.1.1', threatData: { riskScore: 80 }, ttlSeconds: 300 });
    await store.clearThreat({ applicationId: 'app', dimension: 'ip', value: '1.1.1.1' });
    expect(redis.del).toHaveBeenCalledWith('threat:app:ip:1.1.1.1');
  });

  test('isAvailable returns false when Redis is down', async () => {
    const redis = makeMockRedis('ping');
    const store = new ThreatStateStore(redis);
    expect(await store.isAvailable()).toBe(false);
  });

  test('keys are namespaced — different apps do not clash', async () => {
    const redis = makeMockRedis();
    const storeA = new ThreatStateStore(redis);
    const storeB = new ThreatStateStore(redis);

    await storeA.setThreat({ applicationId: 'app-A', dimension: 'ip', value: '1.2.3.4', threatData: { riskScore: 90, threatType: 'X' }, ttlSeconds: 60 });

    const { threats } = await storeB.getThreatsForRequest({ applicationId: 'app-B', sourceIp: '1.2.3.4' });
    expect(threats).toHaveLength(0); // Different applicationId → different key → no clash
  });
});
