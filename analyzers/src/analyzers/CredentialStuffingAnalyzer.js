'use strict';

/**
 * CredentialStuffingAnalyzer
 *
 * Detects automated credential-stuffing attacks using multiple behavioral signals.
 *
 * SIGNALS TRACKED:
 *   1. Failed auth count per IP  (many failures from one source)
 *   2. Failed auth count per account  (one account targeted from many IPs)
 *   3. Distinct accounts targeted per IP  (IP spraying across accounts)
 *   4. Distinct IPs per account  (distributed attack on one account)
 *
 * RISK SCORING:
 *   Each signal contributes an independent score. The orchestrator aggregates.
 *   This prevents false positives from a single signal while allowing
 *   multi-signal attacks to score high.
 *
 * LIMITATIONS:
 *   - Cannot detect slow-and-low attacks below the threshold.
 *   - Legitimate users behind shared NAT/VPN will share the IP signal.
 *   - Configure thresholds conservatively for high-NAT environments.
 *   - Threshold tuning is environment-specific; defaults are starting points only.
 */

const { ThreatAnalyzer } = require('./ThreatAnalyzer');
const { SlidingWindow } = require('../../../common/src/utils/SlidingWindow');
const { ThreatDetectionResultBuilder } = require('../../../common/src/models/ThreatDetectionResult');
const logger = require('../../../common/src/utils/logger');

// Endpoints that represent authentication attempts
const AUTH_PATHS = new Set([
  'POST:/api/auth/login',
  'POST:/auth/login',
  'POST:/login',
  'POST:/api/login',
  'POST:/api/token',
  'POST:/oauth/token',
  'POST:/api/users/login',
]);

class CredentialStuffingAnalyzer extends ThreatAnalyzer {
  constructor(config, deps) {
    super('credentialStuffing', config, deps);

    const windowMs = (config.windowSeconds || 60) * 1000;
    const appId = config.applicationId;

    this._ipFailureWindow    = new SlidingWindow(deps.redis, { windowMs, keyPrefix: 'cs:ip:fail',    applicationId: appId });
    this._userFailureWindow  = new SlidingWindow(deps.redis, { windowMs, keyPrefix: 'cs:user:fail',  applicationId: appId });
    this._ipAccountsWindow   = new SlidingWindow(deps.redis, { windowMs, keyPrefix: 'cs:ip:accts',   applicationId: appId });
    this._accountIpsWindow   = new SlidingWindow(deps.redis, { windowMs, keyPrefix: 'cs:acct:ips',   applicationId: appId });

    this._thresholds = {
      maxIpFailures:       config.maxIpFailures      || 20,
      maxUserFailures:     config.maxUserFailures     || 5,
      maxDistinctAccounts: config.maxDistinctAccounts || 10,
      maxDistinctIps:      config.maxDistinctIps      || 8,
    };
  }

  _isAuthEvent(event) {
    return AUTH_PATHS.has(event.endpointId) || (event.metadata && event.metadata.isAuthEndpoint === true);
  }

  _isFailedAuth(event) {
    return event.authSuccess === false || (event.statusCode >= 400 && event.statusCode < 500);
  }

  async analyze(event) {
    if (!this.enabled) return this._noThreat();
    if (!this._isAuthEvent(event)) return this._noThreat();
    if (!this._isFailedAuth(event)) return this._noThreat();

    const builder = new ThreatDetectionResultBuilder();
    builder.setThreatType('CREDENTIAL_STUFFING');

    const ip = event.sourceIp;
    const userId = event.userId || event.metadata?.targetUserId || 'unknown';
    const reqId = event.requestId;

    const [ipFailures, userFailures, distinctAccounts, distinctIps] = await Promise.all([
      this._ipFailureWindow.increment(ip, reqId),
      userId !== 'unknown' ? this._userFailureWindow.increment(userId, reqId) : Promise.resolve(0),
      userId !== 'unknown' ? this._ipAccountsWindow.addDistinct(ip, userId) : Promise.resolve(0),
      userId !== 'unknown' ? this._accountIpsWindow.addDistinct(userId, ip) : Promise.resolve(0),
    ]);

    logger.debug({
      msg: 'CredentialStuffingAnalyzer signals',
      ip, userId, ipFailures, userFailures, distinctAccounts, distinctIps,
    });

    // Signal 1: Many failures from one IP
    if (ipFailures >= this._thresholds.maxIpFailures) {
      const score = Math.min(100, 50 + Math.floor((ipFailures - this._thresholds.maxIpFailures) * 2));
      builder.addContribution({
        analyzerId: 'cs:ip-failures',
        score,
        reason: `${ipFailures} auth failures from IP ${ip} within window`,
        evidence: { ipFailures, threshold: this._thresholds.maxIpFailures },
      });
    }

    // Signal 2: One account targeted many times
    if (userFailures >= this._thresholds.maxUserFailures) {
      const score = Math.min(80, 40 + Math.floor((userFailures - this._thresholds.maxUserFailures) * 3));
      builder.addContribution({
        analyzerId: 'cs:user-failures',
        score,
        reason: `${userFailures} auth failures for user ${userId}`,
        evidence: { userFailures, threshold: this._thresholds.maxUserFailures },
      });
    }

    // Signal 3: One IP spraying many accounts
    if (distinctAccounts >= this._thresholds.maxDistinctAccounts) {
      builder.addContribution({
        analyzerId: 'cs:ip-account-spray',
        score: 85,
        reason: `IP ${ip} targeted ${distinctAccounts} distinct accounts`,
        evidence: { distinctAccounts, threshold: this._thresholds.maxDistinctAccounts },
      });
    }

    // Signal 4: One account attacked from many IPs (distributed)
    if (distinctIps >= this._thresholds.maxDistinctIps) {
      builder.addContribution({
        analyzerId: 'cs:distributed-attack',
        score: 90,
        reason: `Account ${userId} attacked from ${distinctIps} distinct IPs`,
        evidence: { distinctIps, threshold: this._thresholds.maxDistinctIps },
      });
    }

    const result = builder.build(this.config.actionMappings);

    if (result.threatDetected) {
      logger.warn({
        msg: 'CredentialStuffingAnalyzer threat detected',
        requestId: event.requestId,
        applicationId: event.applicationId,
        ip, userId,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
      });
    }

    return result;
  }
}

module.exports = { CredentialStuffingAnalyzer };
