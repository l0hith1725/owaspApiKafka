'use strict';

/**
 * ThreatStateStore — Redis-backed threat signal persistence.
 *
 * RESPONSIBILITY:
 *   Write threat signals produced by analyzers into Redis with TTL.
 *   Read threat signals during gateway enforcement.
 *
 * KEY DESIGN:
 *   threat:{applicationId}:{dimension}:{value}
 *   e.g. threat:myapp:ip:1.2.3.4
 *        threat:myapp:user:user-123
 *        threat:myapp:user-endpoint:user-123:GET:/api/orders/{id}
 *
 *   The applicationId namespace guarantees threats from one application
 *   cannot interfere with another application's enforcement decisions.
 *
 * TTL STRATEGY:
 *   Each threat record has a TTL set by the analyzer (from config).
 *   When the TTL expires, the threat state is automatically removed.
 *   This means a blocked IP is automatically unblocked after the TTL.
 *   The analyzer will re-flag if suspicious behavior continues.
 *
 * FAIL-OPEN vs FAIL-CLOSED:
 *   When Redis is unavailable, gateway enforcement defaults to ALLOW
 *   (fail-open) with a warning log. This prioritizes availability.
 *   Applications requiring strict enforcement should set failClosed=true
 *   in gateway config, which returns BLOCK when Redis is unreachable.
 */

const logger = require('../utils/logger');

const THREAT_KEY_PREFIX = 'threat';

class ThreatStateStore {
  /**
   * @param {Object} redisClient - ioredis instance
   * @param {Object} options
   * @param {boolean} [options.failClosed=false] - Block requests when Redis is down
   */
  constructor(redisClient, { failClosed = false } = {}) {
    this._redis = redisClient;
    this._failClosed = failClosed;
  }

  _buildKey(applicationId, dimension, value) {
    // Sanitize to prevent key injection
    const safe = str => String(str).replace(/[^a-zA-Z0-9._-]/g, '_');
    return `${THREAT_KEY_PREFIX}:${safe(applicationId)}:${safe(dimension)}:${safe(value)}`;
  }

  /**
   * Write a threat signal to Redis.
   * Called by analyzers after detecting suspicious behavior.
   *
   * @param {Object} params
   * @param {string} params.applicationId
   * @param {string} params.dimension     - "ip" | "user" | "user-endpoint" | etc.
   * @param {string} params.value         - The dimension's value (e.g. an IP address)
   * @param {Object} params.threatData    - Full threat record
   * @param {number} params.ttlSeconds    - Auto-expiry duration
   */
  async setThreat({ applicationId, dimension, value, threatData, ttlSeconds }) {
    const key = this._buildKey(applicationId, dimension, value);
    const payload = JSON.stringify({
      ...threatData,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString(),
    });

    try {
      await this._redis.set(key, payload, 'EX', ttlSeconds);
      logger.info({ msg: 'Threat signal written', key, threatType: threatData.threatType, ttlSeconds });
    } catch (err) {
      logger.error({ msg: 'ThreatStateStore.setThreat failed', key, err: err.message });
      // Non-fatal: analyzer proceeds; gateway may miss this signal temporarily
    }
  }

  /**
   * Read all threat signals that apply to a given request.
   * Returns an array of threat records sorted by riskScore descending.
   *
   * @param {Object} params
   * @param {string} params.applicationId
   * @param {string} params.sourceIp
   * @param {string} [params.userId]
   * @param {string} [params.endpointId]
   * @returns {Promise<{threats: Array, redisAvailable: boolean}>}
   */
  async getThreatsForRequest({ applicationId, sourceIp, userId, endpointId }) {
    const keys = [
      this._buildKey(applicationId, 'ip', sourceIp),
    ];

    if (userId) {
      keys.push(this._buildKey(applicationId, 'user', userId));
    }
    if (userId && endpointId) {
      keys.push(this._buildKey(applicationId, 'user-endpoint', `${userId}:${endpointId}`));
    }

    try {
      const pipeline = this._redis.pipeline();
      keys.forEach(k => pipeline.get(k));
      const results = await pipeline.exec();

      const threats = results
        .map(([err, val]) => {
          if (err || !val) return null;
          try { return JSON.parse(val); } catch { return null; }
        })
        .filter(Boolean)
        .sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

      return { threats, redisAvailable: true };
    } catch (err) {
      logger.error({ msg: 'ThreatStateStore.getThreatsForRequest failed', err: err.message });
      return { threats: [], redisAvailable: false };
    }
  }

  /**
   * Remove a threat signal manually (e.g., after a user authenticates successfully).
   */
  async clearThreat({ applicationId, dimension, value }) {
    const key = this._buildKey(applicationId, dimension, value);
    try {
      await this._redis.del(key);
      logger.info({ msg: 'Threat signal cleared', key });
    } catch (err) {
      logger.error({ msg: 'ThreatStateStore.clearThreat failed', key, err: err.message });
    }
  }

  /**
   * Check if Redis is reachable.
   */
  async isAvailable() {
    try {
      await this._redis.ping();
      return true;
    } catch {
      return false;
    }
  }

  get failClosed() {
    return this._failClosed;
  }
}

module.exports = { ThreatStateStore };
