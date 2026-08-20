'use strict';

/**
 * BusinessFlowAbuseAnalyzer
 *
 * Detects suspicious sequences of API operations using configurable state machines.
 *
 * DESIGN:
 *   Applications define "sensitive workflows" in config — ordered sequences of
 *   endpointIds that, when traversed too quickly or too many times, indicate abuse.
 *
 *   Example workflow config:
 *   workflows:
 *     - id: payment-flow
 *       steps: [POST:/api/auth/login, POST:/api/payment-methods, PATCH:/api/account, POST:/api/transfers]
 *       maxCompletionsPerWindow: 2
 *       windowSeconds: 300
 *     - id: otp-abuse
 *       steps: [POST:/api/otp/generate, POST:/api/otp/verify]
 *       maxCompletionsPerWindow: 3
 *       windowSeconds: 60
 *
 * STATE MACHINE:
 *   Each user's progress through a workflow is tracked in Redis as a JSON state object.
 *   On each event, the analyzer checks if the event's endpointId matches the next
 *   expected step. If a workflow completes, the completion count is incremented.
 *   Exceeding maxCompletionsPerWindow triggers a threat signal.
 *
 * LIMITATIONS:
 *   - Step matching is exact (endpointId string match). Wildcard/regex support is future work.
 *   - Non-linear workflows (branches) are not supported; extend WorkflowStateMachine for those.
 *   - A user abandoning a workflow mid-way leaves orphaned state until TTL expires.
 */

const { ThreatAnalyzer } = require('./ThreatAnalyzer');
const { SlidingWindow } = require('../../../common/src/utils/SlidingWindow');
const { ThreatDetectionResultBuilder } = require('../../../common/src/models/ThreatDetectionResult');
const logger = require('../../../common/src/utils/logger');

class BusinessFlowAbuseAnalyzer extends ThreatAnalyzer {
  constructor(config, deps) {
    super('businessFlowAbuse', config, deps);
    this._redis = deps.redis;
    this._appId = config.applicationId;
    this._workflows = config.workflows || [];

    // Per-workflow sliding windows for completion counting
    this._completionWindows = {};
    for (const wf of this._workflows) {
      const windowMs = (wf.windowSeconds || 300) * 1000;
      this._completionWindows[wf.id] = new SlidingWindow(deps.redis, {
        windowMs,
        keyPrefix: `bfa:complete:${wf.id}`,
        applicationId: this._appId,
      });
    }
  }

  _stateKey(workflowId, userId) {
    return `bfa:state:${this._appId}:${workflowId}:${userId}`;
  }

  async _getState(workflowId, userId) {
    try {
      const raw = await this._redis.get(this._stateKey(workflowId, userId));
      return raw ? JSON.parse(raw) : { step: 0, startedAt: null };
    } catch { return { step: 0, startedAt: null }; }
  }

  async _setState(workflowId, userId, state, ttlSeconds = 600) {
    try {
      await this._redis.set(
        this._stateKey(workflowId, userId),
        JSON.stringify(state),
        'EX', ttlSeconds
      );
    } catch (err) {
      logger.error({ msg: 'BusinessFlowAbuseAnalyzer._setState failed', err: err.message });
    }
  }

  async _resetState(workflowId, userId) {
    try {
      await this._redis.del(this._stateKey(workflowId, userId));
    } catch {}
  }

  async analyze(event) {
    if (!this.enabled || !event.userId || this._workflows.length === 0) return this._noThreat();

    const builder = new ThreatDetectionResultBuilder();
    builder.setThreatType('BUSINESS_FLOW_ABUSE');

    for (const workflow of this._workflows) {
      const result = await this._analyzeWorkflow(workflow, event, builder);
      if (result) break; // One workflow match per event is sufficient
    }

    return builder.build(this.config.actionMappings);
  }

  async _analyzeWorkflow(workflow, event, builder) {
    const steps = workflow.steps;
    if (!steps || steps.length === 0) return false;

    const userId = event.userId;
    const endpointId = event.endpointId;

    const state = await this._getState(workflow.id, userId);
    const expectedStep = steps[state.step];

    if (endpointId !== expectedStep) {
      // Not the expected step — check if it's step 0 to restart the workflow
      if (endpointId === steps[0]) {
        await this._setState(workflow.id, userId, { step: 1, startedAt: new Date().toISOString() }, workflow.windowSeconds || 300);
        return true;
      }
      return false;
    }

    const nextStep = state.step + 1;

    if (nextStep >= steps.length) {
      // Workflow completed
      await this._resetState(workflow.id, userId);
      const completions = await this._completionWindows[workflow.id].increment(userId, event.requestId);
      const maxAllowed = workflow.maxCompletionsPerWindow || 2;

      logger.info({ msg: 'BusinessFlow completed', workflowId: workflow.id, userId, completions });

      if (completions > maxAllowed) {
        builder.addContribution({
          analyzerId: `bfa:${workflow.id}`,
          score: Math.min(100, 50 + (completions - maxAllowed) * 15),
          reason: `Workflow "${workflow.id}" completed ${completions}x (max ${maxAllowed}) for user ${userId}`,
          evidence: { workflowId: workflow.id, completions, maxAllowed },
        });
      }
      return true;
    }

    // Advance state
    await this._setState(workflow.id, userId, { step: nextStep, startedAt: state.startedAt || new Date().toISOString() }, workflow.windowSeconds || 300);
    return true;
  }
}

module.exports = { BusinessFlowAbuseAnalyzer };
