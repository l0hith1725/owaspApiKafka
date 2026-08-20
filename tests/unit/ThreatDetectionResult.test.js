'use strict';

const {
  ThreatDetectionResultBuilder,
  resolveRiskLevel,
  defaultActionForRiskLevel,
  noThreat,
  ENFORCEMENT_ACTIONS,
} = require('../../common/src/models/ThreatDetectionResult');

describe('resolveRiskLevel', () => {
  test.each([
    [0,   'LOW'],
    [29,  'LOW'],
    [30,  'MEDIUM'],
    [59,  'MEDIUM'],
    [60,  'HIGH'],
    [79,  'HIGH'],
    [80,  'CRITICAL'],
    [100, 'CRITICAL'],
  ])('score %i → %s', (score, expected) => {
    expect(resolveRiskLevel(score)).toBe(expected);
  });
});

describe('defaultActionForRiskLevel', () => {
  test('LOW → ALLOW', () => expect(defaultActionForRiskLevel('LOW')).toBe(ENFORCEMENT_ACTIONS.ALLOW));
  test('MEDIUM → WARN', () => expect(defaultActionForRiskLevel('MEDIUM')).toBe(ENFORCEMENT_ACTIONS.WARN));
  test('HIGH → RATE_LIMIT', () => expect(defaultActionForRiskLevel('HIGH')).toBe(ENFORCEMENT_ACTIONS.RATE_LIMIT));
  test('CRITICAL → BLOCK', () => expect(defaultActionForRiskLevel('CRITICAL')).toBe(ENFORCEMENT_ACTIONS.BLOCK));

  test('custom mapping overrides default', () => {
    const result = defaultActionForRiskLevel('MEDIUM', { MEDIUM: ENFORCEMENT_ACTIONS.BLOCK });
    expect(result).toBe(ENFORCEMENT_ACTIONS.BLOCK);
  });
});

describe('ThreatDetectionResultBuilder', () => {
  test('noThreat returns correct defaults', () => {
    const result = noThreat();
    expect(result.threatDetected).toBe(false);
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('LOW');
    expect(result.recommendedAction).toBe(ENFORCEMENT_ACTIONS.ALLOW);
    expect(result.contributions).toHaveLength(0);
  });

  test('single contribution above 30 triggers threatDetected', () => {
    const result = new ThreatDetectionResultBuilder()
      .addContribution({ analyzerId: 'test', score: 50, reason: 'Test threat', evidence: {} })
      .build();
    expect(result.threatDetected).toBe(true);
    expect(result.riskScore).toBe(50);
    expect(result.riskLevel).toBe('MEDIUM');
    expect(result.recommendedAction).toBe(ENFORCEMENT_ACTIONS.WARN);
  });

  test('contribution below 30 does not trigger threat', () => {
    const result = new ThreatDetectionResultBuilder()
      .addContribution({ analyzerId: 'test', score: 20, reason: 'Minor signal', evidence: {} })
      .build();
    expect(result.threatDetected).toBe(false);
  });

  test('multi-signal bonus applies when 2+ signals >= 30', () => {
    const result = new ThreatDetectionResultBuilder()
      .addContribution({ analyzerId: 'a', score: 60, reason: 'A', evidence: {} })
      .addContribution({ analyzerId: 'b', score: 50, reason: 'B', evidence: {} })
      .build();
    // max=60, bonus=10 → 70
    expect(result.riskScore).toBe(70);
    expect(result.riskLevel).toBe('HIGH');
  });

  test('score is capped at 100', () => {
    const result = new ThreatDetectionResultBuilder()
      .addContribution({ analyzerId: 'a', score: 95, reason: 'A', evidence: {} })
      .addContribution({ analyzerId: 'b', score: 90, reason: 'B', evidence: {} })
      .build();
    expect(result.riskScore).toBeLessThanOrEqual(100);
  });

  test('result is immutable (frozen)', () => {
    const result = noThreat();
    expect(() => { result.riskScore = 99; }).toThrow();
  });

  test('contributions are preserved in result', () => {
    const result = new ThreatDetectionResultBuilder()
      .addContribution({ analyzerId: 'cs:ip', score: 75, reason: 'IP failures', evidence: { count: 30 } })
      .build();
    expect(result.contributions).toHaveLength(1);
    expect(result.contributions[0].analyzerId).toBe('cs:ip');
    expect(result.contributions[0].evidence.count).toBe(30);
  });
});
