'use strict';

const { SecurityEventBuilder, validateSecurityEvent } = require('../../common/src/models/SecurityEvent');

describe('SecurityEventBuilder', () => {
  const mandatory = {
    applicationId: 'test-app',
    sourceIp: '1.2.3.4',
    httpMethod: 'GET',
    path: '/api/orders/1',
    endpointId: 'GET:/api/orders/{id}',
    statusCode: 200,
  };

  test('builds a valid event with mandatory fields', () => {
    const event = new SecurityEventBuilder()
      .setMandatory(mandatory)
      .build();

    expect(event.applicationId).toBe('test-app');
    expect(event.requestId).toBeDefined();
    expect(event.timestamp).toBeDefined();
    expect(event.userId).toBeNull();
  });

  test('throws if mandatory fields are missing', () => {
    expect(() => {
      new SecurityEventBuilder().build();
    }).toThrow('mandatory');
  });

  test('throws if specific mandatory field missing', () => {
    const { statusCode, ...rest } = mandatory;
    expect(() => {
      new SecurityEventBuilder().setMandatory(rest).build();
    }).toThrow('statusCode');
  });

  test('sets optional auth context', () => {
    const event = new SecurityEventBuilder()
      .setMandatory(mandatory)
      .setAuthContext({ userId: 'user-1', tenantId: null, authenticationType: 'JWT', authSuccess: true })
      .build();
    expect(event.userId).toBe('user-1');
    expect(event.authenticationType).toBe('JWT');
    expect(event.authSuccess).toBe(true);
  });

  test('sets resource context', () => {
    const event = new SecurityEventBuilder()
      .setMandatory(mandatory)
      .setResourceContext({ resourceType: 'order', resourceId: '1', action: 'READ' })
      .build();
    expect(event.resourceType).toBe('order');
    expect(event.resourceId).toBe('1');
    expect(event.action).toBe('READ');
  });

  test('result is frozen (immutable)', () => {
    const event = new SecurityEventBuilder().setMandatory(mandatory).build();
    expect(() => { event.applicationId = 'hacked'; }).toThrow();
  });

  test('metadata merges correctly', () => {
    const event = new SecurityEventBuilder()
      .setMandatory(mandatory)
      .setMetadata({ ownerUserId: 'user-2' })
      .setMetadata({ isAuthEndpoint: true })
      .build();
    expect(event.metadata.ownerUserId).toBe('user-2');
    expect(event.metadata.isAuthEndpoint).toBe(true);
  });
});

describe('validateSecurityEvent', () => {
  const valid = {
    requestId: 'req-1',
    applicationId: 'app-1',
    timestamp: new Date().toISOString(),
    sourceIp: '1.2.3.4',
    httpMethod: 'POST',
    path: '/api/login',
    endpointId: 'POST:/api/login',
    statusCode: 401,
  };

  test('passes a valid event', () => {
    const { valid: v, errors } = validateSecurityEvent(valid);
    expect(v).toBe(true);
    expect(errors).toHaveLength(0);
  });

  test('fails when mandatory field missing', () => {
    const { applicationId, ...rest } = valid;
    const { valid: v, errors } = validateSecurityEvent(rest);
    expect(v).toBe(false);
    expect(errors.some(e => e.includes('applicationId'))).toBe(true);
  });

  test('fails on invalid statusCode', () => {
    const { valid: v, errors } = validateSecurityEvent({ ...valid, statusCode: 999 });
    expect(v).toBe(false);
  });

  test('fails on invalid timestamp', () => {
    const { valid: v, errors } = validateSecurityEvent({ ...valid, timestamp: 'not-a-date' });
    expect(v).toBe(false);
  });
});
