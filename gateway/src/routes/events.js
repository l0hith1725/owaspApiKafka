'use strict';

/**
 * Security Event Ingestion API
 *
 * Allows non-proxy integrations (e.g., Spring Boot, Python, Go apps) to POST
 * security events directly to the platform without going through the reverse proxy.
 *
 * This is the "HTTP security-event API" integration mechanism.
 *
 * Authentication: API key via X-API-Key header.
 * Applications must register their applicationId and API key in gateway config.
 */

const express = require('express');
const router = express.Router();
const { validateSecurityEvent } = require('../../../common/src/models/SecurityEvent');
const logger = require('../../../common/src/utils/logger');

function buildEventIngestionRouter({ eventProducer, apiKeys }) {
  // Simple API key auth — replace with mTLS or OAuth for production
  function authenticate(req, res, next) {
    const key = req.headers['x-api-key'];
    const appId = req.headers['x-application-id'];

    if (!key || !appId || apiKeys[appId] !== key) {
      logger.warn({ msg: 'Unauthorized event ingestion attempt', appId, ip: req.ip });
      return res.status(401).json({ error: 'Unauthorized' });
    }
    req.applicationId = appId;
    next();
  }

  /**
   * POST /api/security-events
   * Body: SecurityEvent JSON
   *
   * Used by applications that cannot use the reverse proxy integration.
   * The application constructs and POSTs normalized events after each API call.
   */
  router.post('/security-events', authenticate, async (req, res) => {
    const event = { ...req.body, applicationId: req.applicationId };

    const { valid, errors } = validateSecurityEvent(event);
    if (!valid) {
      return res.status(400).json({ error: 'Invalid event', details: errors });
    }

    await eventProducer.publishEvent(event);

    logger.info({ msg: 'Security event ingested via HTTP API', requestId: event.requestId, applicationId: event.applicationId });
    res.status(202).json({ accepted: true, requestId: event.requestId });
  });

  /**
   * POST /api/security-events/batch
   * Body: { events: SecurityEvent[] }
   *
   * Batch ingestion for high-throughput applications.
   */
  router.post('/security-events/batch', authenticate, async (req, res) => {
    const { events } = req.body;
    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'events must be a non-empty array' });
    }
    if (events.length > 100) {
      return res.status(400).json({ error: 'Batch size limit is 100 events' });
    }

    const results = [];
    for (const event of events) {
      const stamped = { ...event, applicationId: req.applicationId };
      const { valid, errors } = validateSecurityEvent(stamped);
      if (!valid) {
        results.push({ requestId: event.requestId, accepted: false, errors });
        continue;
      }
      await eventProducer.publishEvent(stamped);
      results.push({ requestId: event.requestId, accepted: true });
    }

    res.status(202).json({ results });
  });

  /**
   * GET /api/health
   */
  router.get('/health', (req, res) => {
    res.json({ status: 'ok', service: 'api-threat-gateway', timestamp: new Date().toISOString() });
  });

  return router;
}

module.exports = { buildEventIngestionRouter };
