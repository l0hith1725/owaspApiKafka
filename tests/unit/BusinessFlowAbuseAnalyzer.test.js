'use strict';

const { BusinessFlowAbuseAnalyzer } = require('../../analyzers/src/analyzers/BusinessFlowAbuseAnalyzer');

function makeMockRedis() {
  const kv = {};
  const sets = {};
  return {
    get:  jest.fn(async (key) => kv[key] || null),
    set:  jest.fn(async (key, val) => { kv[key] = val; return 'OK'; }),
    del:  jest.fn(async (key) => { delete kv[key]; return 1; }),
    eval: jest.fn(async (script, numKeys, key, now, windowMs, member, ttl) => {
      if (!sets[key]) sets[key] = new Map();
      const cutoff = Number(now) - Number(windowMs);
      for (const [m, s] of sets[key]) { if (s <= cutoff) sets[key].delete(m); }
      sets[key].set(member, Number(now));
      return sets[key].size;
    }),
    _kv: kv, _sets: sets,
  };
}

const WORKFLOW = {
  id: 'payment-flow',
  steps: ['POST:/api/auth/login', 'POST:/api/payment-methods', 'PATCH:/api/account', 'POST:/api/transfers'],
  maxCompletionsPerWindow: 2,
  windowSeconds: 300,
};

function makeEvent(endpointId, userId = 'user-1') {
  return {
    requestId: `req-${Math.random().toString(36).slice(2)}`,
    applicationId: 'test-app',
    timestamp: new Date().toISOString(),
    sourceIp: '1.2.3.4',
    httpMethod: endpointId.split(':')[0],
    path: endpointId.split(':')[1],
    endpointId,
    statusCode: 200,
    userId,
    authSuccess: true,
    metadata: {},
  };
}

async function completeFlow(analyzer, userId = 'user-1') {
  for (const step of WORKFLOW.steps) {
    await analyzer.analyze(makeEvent(step, userId));
  }
}

describe('BusinessFlowAbuseAnalyzer', () => {
  let redis;
  let analyzer;

  beforeEach(() => {
    redis = makeMockRedis();
    analyzer = new BusinessFlowAbuseAnalyzer(
      { applicationId: 'test-app', enabled: true, workflows: [WORKFLOW] },
      { redis }
    );
  });

  test('no threat for unrelated endpoint', async () => {
    const result = await analyzer.analyze(makeEvent('GET:/api/dashboard'));
    expect(result.threatDetected).toBe(false);
  });

  test('no threat for unauthenticated user', async () => {
    const event = { ...makeEvent('POST:/api/auth/login'), userId: null };
    const result = await analyzer.analyze(event);
    expect(result.threatDetected).toBe(false);
  });

  test('no threat after 1 workflow completion (within limit)', async () => {
    await completeFlow(analyzer);
    const result = await analyzer.analyze(makeEvent('GET:/api/dashboard'));
    expect(result.threatDetected).toBe(false);
  });

  test('no threat after exactly maxCompletionsPerWindow completions', async () => {
    await completeFlow(analyzer);
    await completeFlow(analyzer);
    // Should still be within limit (2 allowed)
    const result = await analyzer.analyze(makeEvent('GET:/api/dashboard'));
    expect(result.threatDetected).toBe(false);
  });

  test('detects abuse after exceeding maxCompletionsPerWindow', async () => {
    // Complete flow 3 times (max is 2)
    await completeFlow(analyzer);
    await completeFlow(analyzer);
    let result;
    for (const step of WORKFLOW.steps) {
      result = await analyzer.analyze(makeEvent(step));
    }
    expect(result.threatDetected).toBe(true);
    expect(result.contributions.some(c => c.analyzerId.includes('payment-flow'))).toBe(true);
  });

  test('different users tracked independently', async () => {
    // user-1 completes 3 flows (abusive)
    await completeFlow(analyzer, 'user-1');
    await completeFlow(analyzer, 'user-1');
    await completeFlow(analyzer, 'user-1');

    // user-2 completes 1 flow (normal)
    await completeFlow(analyzer, 'user-2');
    const normalResult = await analyzer.analyze(makeEvent('GET:/api/ok', 'user-2'));
    expect(normalResult.threatDetected).toBe(false);
  });

  test('disabled analyzer returns no threat', async () => {
    const disabled = new BusinessFlowAbuseAnalyzer(
      { applicationId: 'test-app', enabled: false, workflows: [WORKFLOW] },
      { redis }
    );
    const result = await disabled.analyze(makeEvent('POST:/api/auth/login'));
    expect(result.threatDetected).toBe(false);
  });
});
