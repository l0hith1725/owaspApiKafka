'use strict';

/**
 * BOLAAnalyzer — Broken Object Level Authorization (OWASP API1)
 *
 * IMPORTANT LIMITATIONS:
 *   True BOLA detection requires understanding the application's authorization model:
 *   "Is user X actually authorized to access resource Y?"
 *   The platform CANNOT make this determination without application-specific context.
 *
 *   What this analyzer CAN detect:
 *   1. A user accessing an unusually large number of distinct resource IDs in a window.
 *      (e.g., scanning /api/orders/1, /api/orders/2, ... /api/orders/999)
 *   2. A user accessing resource IDs that are not their own when the application
 *      provides an `ownerUserId` field in the event metadata.
 *   3. Sequential/enumerable resource ID access patterns.
 *
 *   What this analyzer CANNOT detect:
 *   - Whether a specific resource ID access is authorized (requires app context).
 *   - Multi-hop authorization chains.
 *   - Role-based access where many resources are legitimately accessible.
 *
 *   INTEGRATION GUIDANCE:
 *   For maximum accuracy, the application should set event.metadata.ownerUserId
 *   on every resource access event. This tells the analyzer who actually owns the resource.
 *
 *   Example event for /api/orders/123 accessed by user-456 who doesn't own it:
 *   {
 *     userId: "user-456",
 *     resourceType: "order",
 *     resourceId: "123",
 *     action: "READ",
 *     metadata: { ownerUserId: "user-789" }  // ← app provides this
 *   }
 *
 * SIGNALS:
 *   1. Distinct resource IDs accessed by one user per window (high-velocity scanning)
 *   2. Cross-ownership access when ownerUserId is available
 *   3. Sequential numeric resource ID enumeration
 */

const { ThreatAnalyzer } = require('./ThreatAnalyzer');
const { SlidingWindow } = require('../../../common/src/utils/SlidingWindow');
const { ThreatDetectionResultBuilder } = require('../../../common/src/models/ThreatDetectionResult');
const logger = require('../../../common/src/utils/logger');

class BOLAAnalyzer extends ThreatAnalyzer {
  constructor(config, deps) {
    super('bola', config, deps);

    const windowMs = (config.windowSeconds || 120) * 1000;
    const appId = config.applicationId;

    // Track distinct resourceIds accessed per user per resourceType
    this._userResourceWindow = new SlidingWindow(deps.redis, {
      windowMs,
      keyPrefix: 'bola:user:resources',
      applicationId: appId,
    });

    this._thresholds = {
      maxDistinctResources:    config.maxDistinctResources    || 50,
      maxCrossOwnershipAccess: config.maxCrossOwnershipAccess || 3,
    };

    // Count cross-ownership access per user in-memory per window (lightweight)
    this._crossOwnershipCounts = new Map();
  }

  _isResourceEvent(event) {
    return !!(event.resourceType && event.resourceId);
  }

  _isNumericSequential(resourceId) {
    return /^\d+$/.test(String(resourceId));
  }

  async analyze(event) {
    if (!this.enabled) return this._noThreat();
    if (!event.userId) return this._noThreat();
    if (!this._isResourceEvent(event)) return this._noThreat();
    if (event.action === 'WRITE' || event.action === 'DELETE') {
      // Write operations have different authorization semantics; don't flag as BOLA
      return this._noThreat();
    }

    const builder = new ThreatDetectionResultBuilder();
    builder.setThreatType('BOLA');

    const userId = event.userId;
    const resourceType = event.resourceType;
    const resourceId = event.resourceId;
    const ownerUserId = event.metadata?.ownerUserId;

    // Dimension: user accessing this resource type
    const dimension = `${userId}:${resourceType}`;

    // Track distinct resource IDs accessed by this user for this resource type
    const distinctCount = await this._userResourceWindow.addDistinct(dimension, resourceId);

    // Signal 1: High-velocity resource enumeration
    if (distinctCount >= this._thresholds.maxDistinctResources) {
      const score = Math.min(90, 50 + Math.floor((distinctCount - this._thresholds.maxDistinctResources) * 0.5));
      builder.addContribution({
        analyzerId: 'bola:resource-enumeration',
        score,
        reason: `User ${userId} accessed ${distinctCount} distinct ${resourceType} resources in window`,
        evidence: { distinctCount, resourceType, threshold: this._thresholds.maxDistinctResources },
      });
    }

    // Signal 2: Cross-ownership access (requires app to provide ownerUserId)
    if (ownerUserId && ownerUserId !== userId) {
      const countKey = `${userId}:${resourceType}`;
      const current = (this._crossOwnershipCounts.get(countKey) || 0) + 1;
      this._crossOwnershipCounts.set(countKey, current);

      if (current >= this._thresholds.maxCrossOwnershipAccess) {
        builder.addContribution({
          analyzerId: 'bola:cross-ownership',
          score: 75,
          reason: `User ${userId} accessed ${current} resources owned by other users`,
          evidence: { crossOwnershipCount: current, resourceType, accessingUser: userId, resourceOwner: ownerUserId },
        });
      }
    }

    // Signal 3: Sequential numeric enumeration — moderate risk, context-dependent
    if (this._isNumericSequential(resourceId) && distinctCount > 10) {
      builder.addContribution({
        analyzerId: 'bola:sequential-enumeration',
        score: 35,
        reason: `User ${userId} accessing sequential numeric ${resourceType} IDs`,
        evidence: { resourceId, distinctCount },
      });
    }

    const result = builder.build(this.config.actionMappings);

    if (result.threatDetected) {
      logger.warn({
        msg: 'BOLAAnalyzer threat detected',
        requestId: event.requestId,
        applicationId: event.applicationId,
        userId, resourceType, resourceId, distinctCount,
        riskScore: result.riskScore,
      });
    }

    return result;
  }
}

module.exports = { BOLAAnalyzer };
