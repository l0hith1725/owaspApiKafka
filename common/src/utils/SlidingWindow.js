'use strict';

/**
 * Redis-backed sliding window counter.
 *
 * WHY SLIDING WINDOW vs FIXED WINDOW:
 *   Fixed windows reset at clock boundaries. An attacker can send N-1 requests
 *   just before midnight and N-1 just after, doubling their effective rate.
 *   A sliding window tracks the actual rolling time period, eliminating boundary abuse.
 *
 * IMPLEMENTATION:
 *   Uses a Redis sorted set where each member is `${requestId}:${timestamp}` and
 *   the score is the Unix timestamp in milliseconds. On each increment:
 *     1. Remove members older than (now - windowMs)
 *     2. Add current event
 *     3. Count remaining members
 *
 * MEMORY: Each entry is O(1) in the sorted set. For a 60-second window with
 *   1000 req/min, that's ~1000 members per key — negligible.
 *
 * DISTRIBUTED SAFETY: All operations use a Lua script for atomicity,
 *   so multiple analyzer instances share state correctly.
 */

const SLIDING_WINDOW_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local member = ARGV[3]
local ttl_seconds = tonumber(ARGV[4])

-- Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)

-- Add current entry
redis.call('ZADD', key, now, member)

-- Set TTL so orphaned keys expire
redis.call('EXPIRE', key, ttl_seconds)

-- Return count within window
return redis.call('ZCARD', key)
`;

const COUNT_DISTINCT_SCRIPT = `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local ttl_seconds = tonumber(ARGV[3])

-- Remove expired entries
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)
redis.call('EXPIRE', key, ttl_seconds)

-- Return count (caller tracks distinct values as member names)
return redis.call('ZCARD', key)
`;

class SlidingWindow {
  /**
   * @param {Object} redisClient  - ioredis client
   * @param {Object} options
   * @param {number} options.windowMs      - Window duration in milliseconds
   * @param {string} options.keyPrefix     - Redis key prefix, e.g. "sw:cs:fail"
   * @param {string} options.applicationId - Namespaces keys per application
   */
  constructor(redisClient, { windowMs, keyPrefix, applicationId }) {
    this._redis = redisClient;
    this._windowMs = windowMs;
    this._keyPrefix = keyPrefix;
    this._appId = applicationId;
    this._ttlSeconds = Math.ceil((windowMs * 2) / 1000); // 2x window for safety
  }

  /**
   * Build a namespaced Redis key.
   * Multi-tenant safe: applicationId is always part of the key.
   */
  _buildKey(...parts) {
    return `${this._keyPrefix}:${this._appId}:${parts.join(':')}`;
  }

  /**
   * Increment counter for a given dimension and return the count within the window.
   * @param {string} dimension  - e.g. sourceIp value, userId value
   * @param {string} eventId    - Unique ID for this event (prevents exact duplicate counting)
   * @returns {Promise<number>}
   */
  async increment(dimension, eventId) {
    const key = this._buildKey(dimension);
    const now = Date.now();
    const member = `${eventId}:${now}`;

    try {
      const count = await this._redis.eval(
        SLIDING_WINDOW_SCRIPT,
        1,
        key,
        now,
        this._windowMs,
        member,
        this._ttlSeconds
      );
      return Number(count);
    } catch (err) {
      // Fail open: return 0 so analysis degrades gracefully, not explosively
      console.error({ msg: 'SlidingWindow.increment failed', key, err: err.message });
      return 0;
    }
  }

  /**
   * Track a distinct value (e.g., distinct IPs per userId) within the window.
   * Uses the distinct value itself as the sorted-set member.
   * @param {string} dimension      - e.g. userId
   * @param {string} distinctValue  - e.g. sourceIp
   * @returns {Promise<number>} count of distinct values seen in window
   */
  async addDistinct(dimension, distinctValue) {
    const key = this._buildKey('distinct', dimension);
    const now = Date.now();

    try {
      // ZADD with the value as member; score = now for expiry
      await this._redis.zadd(key, now, distinctValue);
      const count = await this._redis.eval(
        COUNT_DISTINCT_SCRIPT,
        1,
        key,
        now,
        this._windowMs,
        this._ttlSeconds
      );
      return Number(count);
    } catch (err) {
      console.error({ msg: 'SlidingWindow.addDistinct failed', key, err: err.message });
      return 0;
    }
  }

  /**
   * Read current count without incrementing.
   */
  async count(dimension) {
    const key = this._buildKey(dimension);
    const now = Date.now();
    try {
      await this._redis.zremrangebyscore(key, '-inf', now - this._windowMs);
      return await this._redis.zcard(key);
    } catch (err) {
      return 0;
    }
  }
}

module.exports = { SlidingWindow };
