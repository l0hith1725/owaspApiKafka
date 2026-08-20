'use strict';

/**
 * Gateway Enforcement Middleware
 *
 * Runs on every inbound request BEFORE it is proxied to the upstream application.
 *
 * FLOW:
 *   1. Extract security context (IP, userId, endpointId, etc.)
 *   2. Query Redis for existing threat signals
 *   3. Evaluate enforcement policy
 *   4. BLOCK / WARN / RATE-LIMIT or ALLOW
 *   5. Publish SecurityEvent to Kafka (non-blocking)
 *   6. Forward to upstream (if allowed)
 *
 * FAIL-OPEN vs FAIL-CLOSED:
 *   If Redis is unavailable AND failClosed=true → BLOCK with 503.
 *   If Redis is unavailable AND failClosed=false → ALLOW with warning log.
 *   Default: fail-open (preserves availability; behavioral history in Redis continues to protect).
 *
 * LATENCY IMPACT:
 *   One Redis pipeline read (2-3 keys) adds ~1-2ms per request.
 *   Kafka publish is fully async (fire-and-forget) and adds 0ms to response time.
 */

const { ENFORCEMENT_ACTIONS } = require('../../../common/src/models/ThreatDetectionResult');
const logger = require('../../../common/src/utils/logger');

function buildEnforcementMiddleware({ threatStore, eventProducer, config }) {
  const failClosed = config.gateway?.failClosed || false;
  const applicationId = config.applicationId;

  return async function enforcementMiddleware(req, res, next) {
    const start = Date.now();

    // ── 1. Extract security context ──────────────────────────────────────────
    const sourceIp = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '0.0.0.0';
    const userId = req.user?.id || req.user?.sub || null;
    const endpointId = `${req.method}:${req.route?.path || req.path}`;
    const requestId = req.headers['x-request-id'] || require('crypto').randomUUID();

    req.securityContext = { requestId, sourceIp, userId, endpointId, applicationId };
    res.setHeader('x-request-id', requestId);

    // ── 2. Query Redis for threat signals ─────────────────────────────────────
    const { threats, redisAvailable } = await threatStore.getThreatsForRequest({
      applicationId,
      sourceIp,
      userId,
      endpointId,
    });

    // ── 3. Handle Redis unavailability ────────────────────────────────────────
    if (!redisAvailable) {
      logger.warn({ msg: 'Redis unavailable during enforcement', requestId, sourceIp, userId });
      if (failClosed) {
        return res.status(503).json({ error: 'Service temporarily unavailable', requestId });
      }
      // Fail-open: proceed without enforcement
      return _proceed(req, res, next, requestId, start, eventProducer, applicationId);
    }

    // ── 4. Evaluate enforcement policy ────────────────────────────────────────
    if (threats.length === 0) {
      return _proceed(req, res, next, requestId, start, eventProducer, applicationId);
    }

    const topThreat = threats[0]; // Already sorted by riskScore desc
    const action = topThreat.recommendedAction || ENFORCEMENT_ACTIONS.ALLOW;

    logger.warn({
      msg: 'Threat signal found for request',
      requestId,
      action,
      sourceIp,
      userId,
      threatType: topThreat.threatType,
      riskScore: topThreat.riskScore,
      riskLevel: topThreat.riskLevel,
      applicationId,
    });

    if (action === ENFORCEMENT_ACTIONS.BLOCK) {
      return res.status(403).json({
        error: 'Request blocked due to suspicious activity',
        requestId,
        threatId: topThreat.detectionId,
      });
    }

    if (action === ENFORCEMENT_ACTIONS.RATE_LIMIT) {
      res.setHeader('Retry-After', '60');
      return res.status(429).json({
        error: 'Too many requests — rate limited due to suspicious activity',
        requestId,
      });
    }

    if (action === ENFORCEMENT_ACTIONS.WARN) {
      res.setHeader('x-threat-warning', topThreat.threatType);
      // Falls through to next()
    }

    return _proceed(req, res, next, requestId, start, eventProducer, applicationId);
  };
}

async function _proceed(req, res, next, requestId, start, eventProducer, applicationId) {
  // Intercept response to capture statusCode for the security event
  const originalJson = res.json.bind(res);
  res.json = function(body) {
    _publishEvent(req, res, requestId, start, eventProducer, applicationId);
    return originalJson(body);
  };

  // Also capture non-JSON responses
  const originalEnd = res.end.bind(res);
  res.end = function(...args) {
    if (!res._securityEventPublished) {
      _publishEvent(req, res, requestId, start, eventProducer, applicationId);
    }
    return originalEnd(...args);
  };

  next();
}

function _publishEvent(req, res, requestId, start, eventProducer, applicationId) {
  if (res._securityEventPublished) return;
  res._securityEventPublished = true;

  const ctx = req.securityContext || {};
  const event = {
    requestId,
    applicationId,
    timestamp: new Date().toISOString(),
    sourceIp: ctx.sourceIp,
    httpMethod: req.method,
    path: req.path,
    endpointId: ctx.endpointId,
    statusCode: res.statusCode,
    userId: ctx.userId || null,
    tenantId: req.user?.tenantId || null,
    authenticationType: req.user ? 'JWT' : 'NONE',
    authSuccess: req.user ? true : (res.statusCode === 401 ? false : null),
    resourceType: req.resourceType || null,
    resourceId: req.resourceId || null,
    action: req.resourceAction || null,
    userAgent: req.headers['user-agent'] || null,
    requestDurationMs: Date.now() - start,
    metadata: req.securityMetadata || {},
  };

  // Fire and forget — never block the response
  setImmediate(() => eventProducer.publishEvent(event).catch(() => {}));
}

module.exports = { buildEnforcementMiddleware };
