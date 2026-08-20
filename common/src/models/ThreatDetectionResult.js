'use strict';

/**
 * Risk levels mapped to score ranges.
 * Analyzers contribute scores; the platform aggregates and determines action.
 */
const RISK_LEVELS = Object.freeze({
  LOW: { label: 'LOW', min: 0, max: 29 },
  MEDIUM: { label: 'MEDIUM', min: 30, max: 59 },
  HIGH: { label: 'HIGH', min: 60, max: 79 },
  CRITICAL: { label: 'CRITICAL', min: 80, max: 100 },
});

/**
 * Enforcement actions the gateway can apply.
 */
const ENFORCEMENT_ACTIONS = Object.freeze({
  ALLOW: 'ALLOW',
  WARN: 'WARN',
  RATE_LIMIT: 'RATE_LIMIT',
  BLOCK: 'BLOCK',
});

/**
 * Resolves a numeric risk score to a risk level label.
 * @param {number} score 0-100
 * @returns {string}
 */
function resolveRiskLevel(score) {
  if (score >= 80) return RISK_LEVELS.CRITICAL.label;
  if (score >= 60) return RISK_LEVELS.HIGH.label;
  if (score >= 30) return RISK_LEVELS.MEDIUM.label;
  return RISK_LEVELS.LOW.label;
}

/**
 * Maps a risk level to a default enforcement action.
 * Applications can override this mapping via configuration.
 */
function defaultActionForRiskLevel(riskLevel, customMappings = {}) {
  const defaults = {
    LOW: ENFORCEMENT_ACTIONS.ALLOW,
    MEDIUM: ENFORCEMENT_ACTIONS.WARN,
    HIGH: ENFORCEMENT_ACTIONS.RATE_LIMIT,
    CRITICAL: ENFORCEMENT_ACTIONS.BLOCK,
  };
  return customMappings[riskLevel] || defaults[riskLevel] || ENFORCEMENT_ACTIONS.ALLOW;
}

/**
 * @typedef {Object} AnalyzerContribution
 * @property {string} analyzerId    - e.g. "credentialStuffing"
 * @property {number} score         - 0-100 contribution
 * @property {string} reason        - Human-readable explanation
 * @property {Object} evidence      - Analyzer-specific evidence (counts, windows, etc.)
 */

/**
 * @typedef {Object} ThreatDetectionResult
 * @property {boolean}                  threatDetected
 * @property {number}                   riskScore           - 0-100 aggregated
 * @property {string}                   riskLevel           - LOW|MEDIUM|HIGH|CRITICAL
 * @property {string}                   threatType          - Primary threat category
 * @property {string}                   recommendedAction   - ALLOW|WARN|RATE_LIMIT|BLOCK
 * @property {string}                   reason              - Human-readable summary
 * @property {AnalyzerContribution[]}   contributions       - Per-analyzer breakdown
 * @property {string}                   detectionId         - Unique detection event ID
 * @property {string}                   timestamp
 */

class ThreatDetectionResultBuilder {
  constructor() {
    this._contributions = [];
    this._threatDetected = false;
    this._threatType = 'NONE';
    this._reason = 'No threat detected';
    this._detectionId = require('crypto').randomUUID();
    this._timestamp = new Date().toISOString();
  }

  addContribution({ analyzerId, score, reason, evidence = {} }) {
    this._contributions.push({ analyzerId, score, reason, evidence });
    if (score >= 30) this._threatDetected = true;
    return this;
  }

  setThreatType(threatType) {
    this._threatType = threatType;
    return this;
  }

  setReason(reason) {
    this._reason = reason;
    return this;
  }

  build(actionMappings = {}) {
    // Aggregate score: take max of contributions to avoid false compounding,
    // but add a small bonus for multiple signals (capped at 100).
    const scores = this._contributions.map(c => c.score);
    const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
    const multiSignalBonus = scores.filter(s => s >= 30).length > 1 ? 10 : 0;
    const aggregatedScore = Math.min(100, maxScore + multiSignalBonus);

    const riskLevel = resolveRiskLevel(aggregatedScore);
    const recommendedAction = defaultActionForRiskLevel(riskLevel, actionMappings);

    // Determine primary threat type from highest-scoring contribution
    if (this._contributions.length > 0) {
      const primary = this._contributions.reduce((a, b) => a.score > b.score ? a : b);
      if (primary.score >= 30 && this._threatType === 'NONE') {
        this._threatType = primary.analyzerId.toUpperCase();
      }
    }

    return Object.freeze({
      threatDetected: this._threatDetected,
      riskScore: aggregatedScore,
      riskLevel,
      threatType: this._threatType,
      recommendedAction,
      reason: this._reason,
      contributions: [...this._contributions],
      detectionId: this._detectionId,
      timestamp: this._timestamp,
    });
  }
}

/**
 * Convenience: return a clean no-threat result.
 */
function noThreat() {
  return new ThreatDetectionResultBuilder().build();
}

module.exports = {
  RISK_LEVELS,
  ENFORCEMENT_ACTIONS,
  resolveRiskLevel,
  defaultActionForRiskLevel,
  ThreatDetectionResultBuilder,
  noThreat,
};
