import { describe, it, expect } from 'vitest';
import { getProtectedRanges, applyStructuralGuards } from '../src/pii/structure.js';
import type { PIIMatch } from '../src/pii/types.js';

describe('Structural Guards (src/pii/structure.ts)', () => {
  it('identifies bracketed markers and line-leading labels', () => {
    const text = '[START OF TRANSCRIPT]\nAgent: Hello\nUser: Hi\n[END OF TRANSCRIPT]';
    const ranges = getProtectedRanges(text);

    expect(ranges.length).toBeGreaterThanOrEqual(4);
    // [START OF TRANSCRIPT]
    expect(text.slice(ranges[0]![0], ranges[0]![1])).toBe('[START OF TRANSCRIPT]');
  });

  it('suppresses heuristic PERSON matches inside protected zones', () => {
    const text = '[START OF TRANSCRIPT]\nAgent: Hello Sarah.';
    // Say a heuristic flagged "TRANSCRIPT" or "Agent" as PERSON
    const matches: PIIMatch[] = [
      {
        type: 'PERSON',
        value: 'TRANSCRIPT',
        start: 10,
        end: 20,
        method: 'winknlp',
      },
      {
        type: 'PERSON',
        value: 'Agent',
        start: 22,
        end: 27,
        method: 'winknlp',
      },
      {
        type: 'PERSON',
        value: 'Sarah',
        start: 35,
        end: 40,
        method: 'rule',
      },
    ];

    const guarded = applyStructuralGuards(matches, text);
    expect(guarded).toHaveLength(1);
    expect(guarded[0]?.value).toBe('Sarah');
  });

  it('NEVER suppresses deterministic types (SSN, CREDIT_CARD, PHONE, EMAIL)', () => {
    const text = 'SSN: 123-45-6789\nCard: 4111 2222 3333 4321\nPhone: (555) 123-4567';
    const matches: PIIMatch[] = [
      {
        type: 'SSN',
        value: '123-45-6789',
        start: 5,
        end: 16,
        method: 'regex',
      },
      {
        type: 'CREDIT_CARD',
        value: '4111 2222 3333 4321',
        start: 23,
        end: 42,
        method: 'regex',
      },
      {
        type: 'PHONE',
        value: '(555) 123-4567',
        start: 50,
        end: 64,
        method: 'regex',
      },
    ];

    const guarded = applyStructuralGuards(matches, text);
    expect(guarded).toHaveLength(3);
    expect(guarded.map((m) => m.value)).toEqual([
      '123-45-6789',
      '4111 2222 3333 4321',
      '(555) 123-4567',
    ]);
  });
});
