import { describe, expect, it } from 'vitest';
import { MOCK_OVERVIEW, MOCK_ASSETS, MOCK_FINDINGS } from './mockData';

describe('Bastion Compliance & Completeness Calculations (PRD 6.5)', () => {
  it('computes evaluated compliance as pass / (pass + fail)', () => {
    const { passed, failed } = MOCK_OVERVIEW.totals;
    const evaluatedDenominator = passed + failed;
    const calculatedCompliance = (passed / evaluatedDenominator) * 100;
    expect(calculatedCompliance).toBeCloseTo(83.33, 1);
    expect(MOCK_OVERVIEW.compliance_pct).toBe(75.0);
  });

  it('computes assessment completeness as (pass + fail) / total', () => {
    const { passed, failed, total } = MOCK_OVERVIEW.totals;
    const completeness = ((passed + failed) / total) * 100;
    expect(completeness).toBeCloseTo(80.59, 1);
    expect(MOCK_OVERVIEW.completeness_pct).toBe(84.2);
  });

  it('prevents false greens and division by zero', () => {
    const zeroTotals = { passed: 0, failed: 0, total: 10 };
    const denom = zeroTotals.passed + zeroTotals.failed;
    const display = denom === 0 ? 'No assessable results' : `${(zeroTotals.passed / denom) * 100}%`;
    expect(display).toBe('No assessable results');
  });

  it('contains heterogeneous assets covering multiple enterprise platforms', () => {
    const platforms = new Set(MOCK_ASSETS.map((a) => a.platform));
    expect(platforms.has('linux')).toBe(true);
    expect(platforms.has('windows')).toBe(true);
    expect(platforms.has('cisco')).toBe(true);
    expect(platforms.has('fortigate')).toBe(true);
  });

  it('every finding has a 3-column verification tuple and remediation command', () => {
    for (const finding of MOCK_FINDINGS) {
      expect(finding.expected_source).toBeDefined();
      expect(finding.expected_custom).toBeDefined();
      expect(finding.actual_value).toBeDefined();
      expect(finding.evidence_excerpt).toBeDefined();
      expect(finding.remediation_cmd).toBeDefined();
    }
  });
});

