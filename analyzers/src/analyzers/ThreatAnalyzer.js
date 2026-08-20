'use strict';

/**
 * ThreatAnalyzer — Abstract base class for all threat analyzers.
 *
 * Each analyzer is responsible for ONE detection concern.
 * Analyzers must NOT coordinate with each other directly.
 * Risk aggregation happens in AnalyzerOrchestrator.
 *
 * CONTRACT:
 *   - analyze(event) → ThreatDetectionResult
 *   - Analyzers are stateless with respect to per-request data;
 *     all state lives in Redis (SlidingWindow / ThreatStateStore).
 *   - Analyzers must be safe to run concurrently across multiple instances.
 *   - Analyzers MUST NOT block on synchronous I/O.
 */

class ThreatAnalyzer {
  /**
   * @param {string}  analyzerId  - Unique identifier, e.g. "credentialStuffing"
   * @param {Object}  config      - Analyzer-specific configuration from YAML/env
   * @param {Object}  deps        - Injected dependencies (redis, logger, etc.)
   */
  constructor(analyzerId, config, deps) {
    if (new.target === ThreatAnalyzer) {
      throw new Error('ThreatAnalyzer is abstract; extend it.');
    }
    this.analyzerId = analyzerId;
    this.config = config;
    this.deps = deps;
    this.enabled = config.enabled !== false;
  }

  /**
   * Analyze a SecurityEvent and return a ThreatDetectionResult.
   * Subclasses MUST override this method.
   *
   * @param {Object} securityEvent - Validated SecurityEvent
   * @returns {Promise<ThreatDetectionResult>}
   */
  async analyze(securityEvent) { // eslint-disable-line no-unused-vars
    throw new Error(`${this.constructor.name}.analyze() not implemented`);
  }

  /**
   * Optional lifecycle hook: called once when the analyzer is initialized.
   */
  async initialize() {}

  /**
   * Optional lifecycle hook: called on graceful shutdown.
   */
  async shutdown() {}

  /**
   * Convenience: return a no-threat result using this analyzer's ID.
   */
  _noThreat() {
    const { noThreat } = require('../../../common/src/models/ThreatDetectionResult');
    return noThreat();
  }
}

module.exports = { ThreatAnalyzer };
