'use strict';

/**
 * Canonical API Security Event model.
 * Framework-agnostic — produced by any integration layer (middleware, proxy, SDK).
 *
 * MANDATORY fields must be present for the platform to function.
 * OPTIONAL fields enrich detection accuracy but are not required.
 */

const { v4: uuidv4 } = require('uuid');

/**
 * @typedef {Object} SecurityEvent
 *
 * -- Identity & Routing (MANDATORY) --
 * @property {string} requestId        - Unique request identifier (UUID)
 * @property {string} applicationId    - Application/service producing this event
 * @property {string} timestamp        - ISO-8601 UTC timestamp
 * @property {string} sourceIp         - Client IP address
 * @property {string} httpMethod       - GET | POST | PUT | PATCH | DELETE | ...
 * @property {string} path             - Raw request path, e.g. /api/orders/123
 * @property {string} endpointId       - Normalized endpoint, e.g. GET:/api/orders/{id}
 * @property {number} statusCode       - HTTP response status code
 *
 * -- Authentication Context (OPTIONAL but strongly recommended) --
 * @property {string|null} userId              - Authenticated user identifier
 * @property {string|null} tenantId            - Tenant in multi-tenant systems
 * @property {string|null} authenticationType  - JWT | API_KEY | SESSION | NONE
 * @property {boolean}     authSuccess         - Whether authentication succeeded
 *
 * -- Resource Context (OPTIONAL — enriches BOLA detection) --
 * @property {string|null} resourceType  - e.g. "order", "account", "payment"
 * @property {string|null} resourceId    - Specific resource identifier
 * @property {string|null} action        - READ | WRITE | DELETE | ADMIN
 *
 * -- Request Metadata (OPTIONAL) --
 * @property {string|null} userAgent
 * @property {number|null} requestDurationMs
 * @property {number|null} responseBodySize
 *
 * -- Application-Specific Context (OPTIONAL) --
 * @property {Object}      metadata      - Arbitrary key-value pairs; framework-specific context
 *
 * IMPORTANT: Do NOT include passwords, tokens, raw credentials, or PII beyond userId.
 * The event is published to Kafka and must not contain sensitive secrets.
 */

class SecurityEventBuilder {
  constructor() {
    this._event = {
      requestId: uuidv4(),
      applicationId: null,
      timestamp: new Date().toISOString(),
      sourceIp: null,
      httpMethod: null,
      path: null,
      endpointId: null,
      statusCode: null,

      // Auth
      userId: null,
      tenantId: null,
      authenticationType: null,
      authSuccess: null,

      // Resource
      resourceType: null,
      resourceId: null,
      action: null,

      // Metadata
      userAgent: null,
      requestDurationMs: null,
      responseBodySize: null,

      metadata: {},
    };
  }

  setMandatory({ applicationId, sourceIp, httpMethod, path, endpointId, statusCode }) {
    Object.assign(this._event, { applicationId, sourceIp, httpMethod, path, endpointId, statusCode });
    return this;
  }

  setAuthContext({ userId, tenantId, authenticationType, authSuccess }) {
    Object.assign(this._event, { userId, tenantId, authenticationType, authSuccess });
    return this;
  }

  setResourceContext({ resourceType, resourceId, action }) {
    Object.assign(this._event, { resourceType, resourceId, action });
    return this;
  }

  setRequestMetadata({ userAgent, requestDurationMs, responseBodySize }) {
    Object.assign(this._event, { userAgent, requestDurationMs, responseBodySize });
    return this;
  }

  setMetadata(metadata) {
    this._event.metadata = { ...this._event.metadata, ...metadata };
    return this;
  }

  build() {
    const mandatory = ['applicationId', 'sourceIp', 'httpMethod', 'path', 'endpointId', 'statusCode'];
    const missing = mandatory.filter(f => this._event[f] === null || this._event[f] === undefined);
    if (missing.length > 0) {
      throw new Error(`SecurityEvent missing mandatory fields: ${missing.join(', ')}`);
    }
    return Object.freeze({ ...this._event });
  }
}

/**
 * Lightweight validation for events received over HTTP or deserialized from Kafka.
 */
function validateSecurityEvent(event) {
  const mandatory = ['requestId', 'applicationId', 'timestamp', 'sourceIp', 'httpMethod', 'path', 'endpointId', 'statusCode'];
  const errors = [];

  for (const field of mandatory) {
    if (!event[field] && event[field] !== 0) {
      errors.push(`Missing mandatory field: ${field}`);
    }
  }

  if (event.statusCode && (typeof event.statusCode !== 'number' || event.statusCode < 100 || event.statusCode > 599)) {
    errors.push('statusCode must be a number between 100 and 599');
  }

  if (event.timestamp && isNaN(Date.parse(event.timestamp))) {
    errors.push('timestamp must be a valid ISO-8601 string');
  }

  return { valid: errors.length === 0, errors };
}

module.exports = { SecurityEventBuilder, validateSecurityEvent };
