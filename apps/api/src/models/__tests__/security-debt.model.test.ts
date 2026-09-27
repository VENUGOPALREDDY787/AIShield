import { describe, expect, it } from 'vitest';
import { SecurityDebtModel } from '../security-debt.model.js';
import { indexNamed, invalidPaths, oid } from './helpers.js';

const minimalDebt = () => ({ repository: oid(), overallScore: 72 });

describe('SecurityDebt model', () => {
  it('accepts a minimal score and applies defaults', () => {
    const debt = new SecurityDebtModel(minimalDebt());

    expect(invalidPaths(debt)).toEqual([]);
    expect(debt.severityBreakdown?.critical).toBe(0);
    expect(debt.categoryBreakdown?.dependency).toBe(0);
    expect(debt.calculation?.openFindingCount).toBe(0);
    expect(debt.calculation?.calculatedAt).toBeInstanceOf(Date);
    expect(debt.scoreExplanation?.methodology).toBe('weighted-severity-v1');
  });

  it('requires a repository and an overall score', () => {
    expect(invalidPaths(new SecurityDebtModel({}))).toEqual(['overallScore', 'repository']);
  });

  it('bounds the score inputs to 0..100', () => {
    expect(
      invalidPaths(new SecurityDebtModel({ repository: oid(), overallScore: 101 })),
    ).toContain('overallScore');
    expect(
      invalidPaths(new SecurityDebtModel({ repository: oid(), overallScore: -1 })),
    ).toContain('overallScore');
    expect(invalidPaths(new SecurityDebtModel({ ...minimalDebt(), previousScore: 120 }))).toContain(
      'previousScore',
    );
  });

  describe('derived fields', () => {
    it('computes delta, grade and trend from the two scores', () => {
      const debt = new SecurityDebtModel({ repository: oid(), overallScore: 80, previousScore: 70 });

      expect(invalidPaths(debt)).toEqual([]);
      expect(debt.delta).toBe(10);
      expect(debt.grade).toBe('B');
      // The score went up, and a higher score is a better repository.
      expect(debt.trend).toBe('improving');
    });

    it('reports a worsening trend for a falling score', () => {
      const debt = new SecurityDebtModel({ repository: oid(), overallScore: 60, previousScore: 74 });
      debt.validateSync();

      expect(debt.delta).toBe(-14);
      expect(debt.trend).toBe('worsening');
      expect(debt.grade).toBe('D');
    });

    it('treats a negligible change as stable', () => {
      const debt = new SecurityDebtModel({ repository: oid(), overallScore: 70, previousScore: 70 });
      debt.validateSync();

      expect(debt.delta).toBe(0);
      expect(debt.trend).toBe('stable');
    });

    it('never overwrites an explicit delta', () => {
      const debt = new SecurityDebtModel({
        repository: oid(),
        overallScore: 80,
        previousScore: 70,
        delta: 3,
      });
      debt.validateSync();

      expect(debt.delta).toBe(3);
    });

    it.each([
      [95, 'A'],
      [90, 'A'],
      [89, 'B'],
      [80, 'B'],
      [70, 'C'],
      [60, 'D'],
      [59, 'F'],
      [0, 'F'],
    ])('grades a score of %i as %s', (score, expectedGrade) => {
      const debt = new SecurityDebtModel({ repository: oid(), overallScore: score as number });
      debt.validateSync();

      expect(debt.grade).toBe(expectedGrade);
    });
  });

  it('accepts a full score explanation', () => {
    const debt = new SecurityDebtModel({
      ...minimalDebt(),
      severityBreakdown: { critical: 2, high: 5, medium: 9, low: 3, info: 0 },
      categoryBreakdown: { security: 8, secret: 2, dependency: 9, debt: 0, aiReasoning: 0 },
      scoreExplanation: {
        formula: 'score = 100 - min(100, SUM(count(severity) * weight(severity)))',
        summary: '9 open findings, dominated by dependencies.',
        penaltyBySeverity: { critical: 20, high: 25 },
        totalPenalty: 45,
        factors: [
          { label: '2 critical findings', impact: -20, detail: 'Each critical costs 10 points' },
        ],
      },
      calculation: { scan: oid(), openFindingCount: 19, modelVersion: 'weighted-severity-v1' },
    });

    expect(invalidPaths(debt)).toEqual([]);
    expect(debt.scoreExplanation?.totalPenalty).toBe(45);
    expect(debt.scoreExplanation?.factors).toHaveLength(1);
  });

  it('caps the number of score explanation factors', () => {
    const factors = Array.from({ length: 21 }, (_value, index) => ({
      label: `factor-${index}`,
      impact: 1,
    }));
    const debt = new SecurityDebtModel({ ...minimalDebt(), scoreExplanation: { factors } });

    expect(invalidPaths(debt)).toContain('scoreExplanation.factors');
  });

  it('declares exactly one current score per repository', () => {
    const index = indexNamed(SecurityDebtModel, 'uniq_repository');

    expect(index?.key).toBe('repository:1');
    expect(index?.options.unique).toBe(true);
  });

  it('indexes the worst-repositories-first leaderboard', () => {
    expect(indexNamed(SecurityDebtModel, 'score_ascending')?.key).toBe('overallScore:1,updatedAt:-1');
  });
});
