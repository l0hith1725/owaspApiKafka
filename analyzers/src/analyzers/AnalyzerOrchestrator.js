'use strict';

/**
 * AnalyzerOrchestrator
 *
 * Runs all enabled analyzers against a SecurityEvent and aggregates results.
 * Writes threat signals to Redis when threats are detected.
 *
 * DESIGN:
 *   - Analyzers run in parallel (Promise.all) for minimal latency.
 *   - Each analyzer is independent; failures in one do not block others.
 *   - Final risk score = max(individual scores) + multi-signal bonus (capped at 100).
 *   - Threat signals are written to Redis keyed by applicationId + dimension.
 */

const { CredentialStuffingAnalyzer } = require('./CredentialStuffingAnalyzer');
const { BOLAAnalyzer } = require('./BOLAAnalyzer');
const { BusinessFlowAbuseAnalyzer } = require('./BusinessFlowAbuseAnalyzer');
const { ThreatStateStore } = require('../../../common/src/services/ThreatStateStore');
const logger = require('../../../common/src/utils/logger');

class AnalyzerOrchestrator {
  constructor(config, deps) {
    this._config = config;
    this._deps = deps;
    this._threatStore = new ThreatStateStore(deps.redis);
    this._analyzers = [];
    this._metrics = deps.metrics || null;
  }

  initialize() {
    const cfg = this._config.analyzers || {};
    const appId = this._config.applicationId;

    const analyzerDefs = [
      { key: 'credentialStuffing', Cls: CredentialStuffingAnalyzer },
      { key: 'bola',               Cls: BOLAAnalyzer },
      { key: 'businessFlowAbuse',  Cls: BusinessFlowAbuseAnalyzer },
    ];

    for (const { key, Cls } of analyzerDefs) {
      const analyzerCfg = { ...( cfg[key] || {}), applicationId: appId };
      if (analyzerCfg.enabled === false) {
        logger.info({ msg: `Analyzer disabled: ${key}` });
        continue;
      }
      const instance = new Cls(analyzerCfg, this._deps);
      this._analyzers.push(instance);
      logger.info({ msg: `Analyzer registered: ${key}` });
    }
  }

  async analyze(securityEvent) {
    if (this._analyzers.length === 0) return;

    const results = await Promise.all(
      this._analyzers.map(async (analyzer) => {
        try {
          const result = await analyzer.analyze(securityEvent);
          return { analyzerId: analyzer.analyzerId, result };
        } catch (err) {
          logger.error({ msg: `Analyzer ${analyzer.analyzerId} threw`, err: err.message, requestId: securityEvent.requestId });
          return null;
        }
      })
    );

    for (const item of results.filter(Boolean)) {
      if (!item.result.threatDetected) continue;

      await this._writeThreatToRedis(securityEvent, item.result);

      if (this._metrics) {
        this._metrics.threatDetected.inc({ analyzer: item.analyzerId, level: item.result.riskLevel });
      }
    }
  }

  async _writeThreatToRedis(event, result) {
    const appId = event.applicationId;
    const ttl = this._config.threatTtlSeconds || 300;

    const threatData = {
      riskScore: result.riskScore,
      riskLevel: result.riskLevel,
      threatType: result.threatType,
      recommendedAction: result.recommendedAction,
      reason: result.reason,
      detectionId: result.detectionId,
      contributions: result.contributions,
    };

    const writes = [];

    if (event.sourceIp) {
      writes.push(this._threatStore.setThreat({
        applicationId: appId,
        dimension: 'ip',
        value: event.sourceIp,
        threatData,
        ttlSeconds: ttl,
      }));
    }

    if (event.userId) {
      writes.push(this._threatStore.setThreat({
        applicationId: appId,
        dimension: 'user',
        value: event.userId,
        threatData,
        ttlSeconds: ttl,
      }));
    }

    await Promise.all(writes);
  }
}

module.exports = { AnalyzerOrchestrator };
