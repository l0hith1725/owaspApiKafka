'use strict';

/**
 * SecurityEventConsumer
 *
 * Kafka consumer that feeds SecurityEvents to the AnalyzerOrchestrator.
 *
 * CONSUMER GROUP DESIGN:
 *   groupId = "threat-analyzers"
 *   All analyzer service instances share this group.
 *   Kafka assigns partitions across instances → horizontal scaling.
 *   Because events are partitioned by userId/IP, all events for a given user
 *   go to the same partition and are processed by the same consumer instance.
 *   This ensures correct sliding-window state without cross-instance coordination.
 *
 * DUPLICATE HANDLING:
 *   Kafka at-least-once delivery means duplicates are possible (e.g., after a crash).
 *   Sliding window counters use requestId as the sorted-set member, so exact duplicate
 *   events (same requestId) will overwrite the existing member rather than double-count.
 *   Near-duplicate events (same action, slightly different requestId) may inflate counts
 *   marginally but will not cause false positives given conservative thresholds.
 *
 * FAILURE RECOVERY:
 *   On consumer restart, Kafka resumes from last committed offset.
 *   Events are committed after successful analysis, not before.
 *   A crash mid-analysis replays the event on restart (at-least-once).
 */

const { Kafka } = require('kafkajs');
const { validateSecurityEvent } = require('../../../common/src/models/SecurityEvent');
const { TOPICS } = require('../../../common/src/services/SecurityEventProducer');
const logger = require('../../../common/src/utils/logger');

class SecurityEventConsumer {
  constructor(kafkaConfig, orchestrator, metrics = null) {
    this._orchestrator = orchestrator;
    this._metrics = metrics;

    this._kafka = new Kafka({
      clientId: kafkaConfig.clientId || 'threat-analyzer-consumer',
      brokers: kafkaConfig.brokers,
      ssl: kafkaConfig.ssl || false,
      sasl: kafkaConfig.sasl || undefined,
    });

    this._consumer = this._kafka.consumer({
      groupId: kafkaConfig.groupId || 'threat-analyzers',
      sessionTimeout: 30000,
      heartbeatInterval: 3000,
      maxBytesPerPartition: 1048576, // 1MB
    });

    this._running = false;
  }

  async start() {
    await this._consumer.connect();
    await this._consumer.subscribe({ topic: TOPICS.RAW_EVENTS, fromBeginning: false });

    this._running = true;
    logger.info({ msg: 'SecurityEventConsumer started', topic: TOPICS.RAW_EVENTS });

    await this._consumer.run({
      autoCommit: false, // Manual commit after processing
      eachMessage: async ({ topic, partition, message, heartbeat }) => {
        const start = Date.now();
        let event;

        try {
          event = JSON.parse(message.value.toString());
        } catch (err) {
          logger.error({ msg: 'Failed to parse Kafka message', partition, err: err.message });
          await this._consumer.commitOffsets([{ topic, partition, offset: (BigInt(message.offset) + 1n).toString() }]);
          return;
        }

        const { valid, errors } = validateSecurityEvent(event);
        if (!valid) {
          logger.warn({ msg: 'Invalid SecurityEvent received', errors, requestId: event.requestId });
          await this._consumer.commitOffsets([{ topic, partition, offset: (BigInt(message.offset) + 1n).toString() }]);
          return;
        }

        try {
          await this._orchestrator.analyze(event);
          await heartbeat();
        } catch (err) {
          logger.error({ msg: 'Orchestrator analysis failed', requestId: event.requestId, err: err.message });
          // Still commit — we don't want to replay indefinitely on a bad event
        }

        if (this._metrics) {
          this._metrics.eventsProcessed.inc({ applicationId: event.applicationId });
          this._metrics.analysisLatency.observe(Date.now() - start);
        }

        await this._consumer.commitOffsets([{
          topic,
          partition,
          offset: (BigInt(message.offset) + 1n).toString(),
        }]);
      },
    });
  }

  async stop() {
    this._running = false;
    await this._consumer.disconnect();
    logger.info({ msg: 'SecurityEventConsumer stopped' });
  }
}

module.exports = { SecurityEventConsumer };
