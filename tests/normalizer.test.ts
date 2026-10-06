import { describe, it, expect } from 'vitest';
import { normalizeMatches } from '../src/pii/normalizer.js';
import type { PIIMatch } from '../src/pii/types.js';

describe('Normalizer and Deduplicator', () => {
  it('deduplicates identical spans preferring regex over winknlp', () => {
    const text = 'Email me at ahmed@example.com today.';
    const matches: PIIMatch[] = [
      {
        type: 'EMAIL',
        value: 'ahmed@example.com',
        start: 12,
        end: 29,
        method: 'winknlp',
        confidence: 0.95,
      },
      {
        type: 'EMAIL',
        value: 'ahmed@example.com',
        start: 12,
        end: 29,
        method: 'regex',
        confidence: 0.99,
      },
    ];

    const result = normalizeMatches(matches, text);
    expect(result).toHaveLength(1);
    expect(result[0]?.method).toBe('regex');
    expect(result[0]?.value).toBe('ahmed@example.com');
  });

  it('drops nested spans contained completely inside an enclosing span', () => {
    const text = 'Call +20 100 123 4567 now.';
    // Say regex detected phone span (5 to 21)
    // And another engine tagged "100" (9 to 12) as a number
    const matches: PIIMatch[] = [
      {
        type: 'MISC',
        value: '100',
        start: 9,
        end: 12,
        method: 'winknlp',
      },
      {
        type: 'PHONE',
        value: '+20 100 123 4567',
        start: 5,
        end: 21,
        method: 'regex',
        confidence: 0.95,
      },
    ];

    const result = normalizeMatches(matches, text);
    expect(result).toHaveLength(1);
    expect(result[0]?.type).toBe('PHONE');
    expect(result[0]?.value).toBe('+20 100 123 4567');
  });

  it('orders matches ascending by start index', () => {
    const text = 'Second: mary@corp.com, First: john@corp.com.';
    const matches: PIIMatch[] = [
      {
        type: 'EMAIL',
        value: 'john@corp.com',
        start: 30,
        end: 43,
        method: 'regex',
      },
      {
        type: 'EMAIL',
        value: 'mary@corp.com',
        start: 8,
        end: 21,
        method: 'regex',
      },
    ];

    const result = normalizeMatches(matches, text);
    expect(result).toHaveLength(2);
    expect(result[0]?.value).toBe('mary@corp.com');
    expect(result[1]?.value).toBe('john@corp.com');
  });

  it('discards matches whose start/end offsets do not match text.slice', () => {
    const text = 'Hello world';
    const matches: PIIMatch[] = [
      {
        type: 'PERSON',
        value: 'Ahmed',
        start: 0,
        end: 5, // text.slice(0,5) is "Hello", not "Ahmed"
        method: 'rule',
      },
    ];

    const result = normalizeMatches(matches, text);
    expect(result).toHaveLength(0);
  });
});
