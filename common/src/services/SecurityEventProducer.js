'use strict';

/**
 * SecurityEventProducer
 *
 * Publishes normalized SecurityEvents to Kafka.
 *
 * TOPIC DESIGN:
 *   security.events.raw         - All API events; consumed by all analyzers
 *   security.events.threats     - Confirmed threat signals from analyzers → gateway
 *
 * PARTITION KEY STRATEGY:
 *   Key = applicationId + ":" + userId (or sourceIp when userId is absent)
 *   WHY: Sliding-window analyzers need to see all events for a given user/IP in order.
 *        Partitioning by userId ensures a single consumer instance handles all events
 *        for that user, enabling stateful in-memory sliding windows without distributed
 *        coordination. Tradeoff: hot partitions if a small number of users generate
 *        massive event volume. Mitigate with a separate Kafka topic for high-volume
 *        IPs if needed.
 *
 * KAFKA UNAVAILABILITY:
 *   If Kafka is down, events are logged to stderr and the request still proceeds.
 *   The gateway does NOT block requests due to Kafka being unavailable — it fails open.
 *   This means behavioral detection temporarily stops, but the service remains available.
 *   Redis threat state (written by previous analyses) continues to protect the gateway.
 */

const { Kafka, CompressionTypes } = require('kafkajs');
const logger = require('../utils/logger');

const TOPICS = Object.freeze({
  RAW_EVENTS: 'security.events.raw',
  THREAT_SIGNALS: 'security.events.threats',
});

class SecurityEventProducer {
  /**
   * @param {Object} kafkaConfig - KafkaJS configuration
   * @param {Object} [options]
   * @param {boolean} [options.enabled=true] - Set false to disable publishing (useful in tests)
   */
  constructor(kafkaConfig, { enabled = true } = {}) {
    this._enabled = enabled;
    if (!enabled) return;

    this._kafka = new Kafka({
      clientId: kafkaConfig.clientId || 'threat-platform-producer',
      brokers: kafkaConfig.brokers,
      ssl: kafkaConfig.ssl || false,
      sasl: kafkaConfig.sasl || undefined,
      retry: { retries: 3, initialRetryTime: 300 },
    });
    this._producer = this._kafka.producer({
      allowAutoTopicCreation: false,
      transactionTimeout: 30000,
    });
    this._connected = false;
  }

  async connect() {
    if (!this._enabled) return;
    try {
      await this._producer.connect();
      this._connected = true;
      logger.info({ msg: 'SecurityEventProducer connected to Kafka' });
    } catch (err) {
      logger.error({ msg: 'SecurityEventProducer failed to connect', err: err.message });
      this._connected = false;
    }
  }

  async disconnect() {
    if (!this._enabled || !this._connected) return;
    await this._producer.disconnect();
    this._connected = false;
  }

  /**
   * Publish a SecurityEvent to the raw events topic.
   * Non-blocking: errors are logged but do not propagate to the caller.
   */
  async publishEvent(securityEvent) {
    if (!this._enabled) return;

    // Partition key: ensures ordered processing per user/IP by a single consumer.
    const partitionKey = securityEvent.userId
      ? `${securityEvent.applicationId}:user:${securityEvent.userId}`
      : `${securityEvent.applicationId}:ip:${securityEvent.sourceIp}`;

    try {
      if (!this._connected) {
        await this.connect();
      }
      await this._producer.send({
        topic: TOPICS.RAW_EVENTS,
        compression: CompressionTypes.GZIP,
        messages: [{
          key: partitionKey,
          value: JSON.stringify(securityEvent),
          headers: {
            applicationId: securityEvent.applicationId,
            requestId: securityEvent.requestId,
            schemaVersion: '1',
          },
        }],
      });
    } catch (err) {
      logger.error({
        msg: 'SecurityEventProducer.publishEvent failed — event dropped',
        requestId: securityEvent.requestId,
        err: err.message,
      });
      // Do not rethrow. The gateway must not be blocked by Kafka failures.
    }
  }

  /**
   * Publish a threat signal (from analyzer → gateway feedback loop).
   */
  async publishThreatSignal(threatSignal) {
    if (!this._enabled) return;

    const partitionKey = `${threatSignal.applicationId}:${threatSignal.dimension}:${threatSignal.value}`;

    try {
      if (!this._connected) await this.connect();
      await this._producer.send({
        topic: TOPICS.THREAT_SIGNALS,
        messages: [{
          key: partitionKey,
          value: JSON.stringify(threatSignal),
        }],
      });
    } catch (err) {
      logger.error({ msg: 'SecurityEventProducer.publishThreatSignal failed', err: err.message });
    }
  }

  get isConnected() { return this._connected; }
}

module.exports = { SecurityEventProducer, TOPICS };
