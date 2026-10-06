import { describe, it, expect } from 'vitest';
import { detectWithWinkNLP } from '../src/pii/wink-detector.js';

describe('WinkNLP Detector', () => {
  it('detects email addresses with exact character offsets', () => {
    const text = 'Contact me at ahmed@example.com for inquiries.';
    const matches = detectWithWinkNLP(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(emailMatch?.start).toBe(14);
    expect(emailMatch?.end).toBe(31);
    expect(text.slice(emailMatch!.start, emailMatch!.end)).toBe('ahmed@example.com');
  });

  it('detects URLs with exact character offsets', () => {
    const text = 'Visit https://example.com for more info.';
    const matches = detectWithWinkNLP(text);

    const urlMatch = matches.find((m) => m.type === 'URL');
    expect(urlMatch).toBeDefined();
    expect(urlMatch?.value).toBe('https://example.com');
    expect(text.slice(urlMatch!.start, urlMatch!.end)).toBe('https://example.com');
  });

  it('detects dates when extractDates option is enabled', () => {
    const text = 'The event was held on April 1, 1976 in California.';
    const matches = detectWithWinkNLP(text, { extractDates: true });

    const dateMatch = matches.find((m) => m.type === 'DATE');
    expect(dateMatch).toBeDefined();
    expect(dateMatch?.value).toBe('April 1, 1976');
    expect(text.slice(dateMatch!.start, dateMatch!.end)).toBe('April 1, 1976');
  });

  it('handles entities surrounded by punctuation (<email>, brackets)', () => {
    const text = 'Send questions to <ahmed@example.com>.';
    const matches = detectWithWinkNLP(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(text.slice(emailMatch!.start, emailMatch!.end)).toBe('ahmed@example.com');
  });

  it('accurately preserves character offsets in mixed Arabic / Unicode text', () => {
    const text = 'اسمي أحمد والبريد الإلكتروني ahmed@example.com للتواصل.';
    const matches = detectWithWinkNLP(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(text.slice(emailMatch!.start, emailMatch!.end)).toBe('ahmed@example.com');
  });

  it('detects multiple entities across sentences', () => {
    const text = 'First user: john@example.com. Second user: mary@company.org on Jan 1st 2024.';
    const matches = detectWithWinkNLP(text, { extractDates: true });

    const emails = matches.filter((m) => m.type === 'EMAIL');
    expect(emails).toHaveLength(2);
    expect(emails[0]?.value).toBe('john@example.com');
    expect(emails[1]?.value).toBe('mary@company.org');

    for (const match of matches) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('demonstrates WinkNLP standard NER limitation: PERSON is not built-in', () => {
    // Under pure WinkNLP NER (no POS heuristic), person names are not detected as entities
    const text = 'My name is Ahmed Maher and I live in Cairo.';
    const matches = detectWithWinkNLP(text);

    const personMatch = matches.find((m) => m.type === 'PERSON');
    expect(personMatch).toBeUndefined();
  });

  it('demonstrates WinkNLP POS-based PROPN heuristic when enabled', () => {
    const text = 'My name is Ahmed Maher.';
    const matches = detectWithWinkNLP(text, { extractProperNounsAsPerson: true });

    const personMatch = matches.find((m) => m.type === 'PERSON');
    expect(personMatch).toBeDefined();
    expect(personMatch?.value).toBe('Ahmed Maher');
    expect(text.slice(personMatch!.start, personMatch!.end)).toBe('Ahmed Maher');
  });

  it('returns empty array for empty or whitespace input', () => {
    expect(detectWithWinkNLP('')).toEqual([]);
    expect(detectWithWinkNLP('   ')).toEqual([]);
  });
});
