import { describe, it, expect } from 'vitest';
import { detectPersons, isPlausibleName } from '../src/pii/person-detector.js';

describe('Person Detector (Anchored)', () => {
  it('fires on each of the 6 anchors on positive examples', () => {
    // 1. name-is
    const m1 = detectPersons('My name is Sarah Jenkins.');
    expect(m1.some((m) => m.value === 'Sarah Jenkins')).toBe(true);

    // 2. self (with straight and curly apostrophe)
    const m2a = detectPersons('I am Michael T. Rodriguez.');
    expect(m2a.some((m) => m.value === 'Michael T. Rodriguez')).toBe(true);
    const m2b = detectPersons('I’m Mike Rodriguez.');
    expect(m2b.some((m) => m.value === 'Mike Rodriguez')).toBe(true);
    const m2c = detectPersons('This is John Doe calling.');
    expect(m2c.some((m) => m.value === 'John Doe')).toBe(true);

    // 3. title
    const m3 = detectPersons('I can help with that, Mr. Rodriguez.');
    expect(m3.some((m) => m.value === 'Rodriguez')).toBe(true);

    // 4. greeting
    const m4a = detectPersons('Hi Sarah, how are you?');
    expect(m4a.some((m) => m.value === 'Sarah')).toBe(true);
    const m4b = detectPersons('No, that’s all. Thanks, Sarah.');
    expect(m4b.some((m) => m.value === 'Sarah')).toBe(true);

    // 5. account
    const m5 = detectPersons('My account might be under Mike Rodriguez.');
    expect(m5.some((m) => m.value === 'Mike Rodriguez')).toBe(true);

    // 6. speaking
    const m6 = detectPersons('Sarah Jenkins speaking, how can I help?');
    expect(m6.some((m) => m.value === 'Sarah Jenkins')).toBe(true);
  });

  it('detects all real names from the reference chat transcript', () => {
    const transcript = `
Agent (System): Thank you for contacting SecureBank Support. My name is Sarah Jenkins. How can I help you today?
User: Hi Sarah. I’m having trouble logging in. My name is Michael T. Rodriguez, but my account might be under Mike Rodriguez.
Agent: I can help with that, Mr. Rodriguez.
User: No, that’s all. Thanks, Sarah.
    `;

    const matches = detectPersons(transcript);
    const foundValues = matches.map((m) => m.value);

    expect(foundValues).toContain('Sarah Jenkins');
    expect(foundValues).toContain('Sarah');
    expect(foundValues).toContain('Michael T. Rodriguez');
    expect(foundValues).toContain('Mike Rodriguez');
    expect(foundValues).toContain('Rodriguez');

    for (const match of matches) {
      expect(transcript.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('does NOT detect false positives from real sample lines', () => {
    const falsePositiveLines = [
      'Test Case ID: PII-TEST-001',
      'Date: 2023-10-27',
      'Source: Customer Support Chat Log',
      '[START OF TRANSCRIPT]',
      'Agent (System): Thank you for contacting SecureBank Support.',
      'Agent: Perfect. And the phone number we have on file is (555) 123-4567.',
      'User: Sure, it’s a Visa ending in 4321.',
      '[END OF TRANSCRIPT]',
    ];

    for (const line of falsePositiveLines) {
      const matches = detectPersons(line);
      const names = matches.map((m) => m.value);

      expect(names).not.toContain('Agent');
      expect(names).not.toContain('System');
      expect(names).not.toContain('Perfect');
      expect(names).not.toContain('Visa');
      expect(names).not.toContain('TRANSCRIPT');
      expect(names).not.toContain('END');
      expect(names).not.toContain('PII-TEST-001');
      expect(names).not.toContain('Customer Support');
      expect(names).not.toContain('for contacting');
    }
  });

  it('supports caller-supplied knownNames', () => {
    const text = 'Visiting Evergreen on business.';
    const matches = detectPersons(text, { knownNames: ['Evergreen'] });
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe('Evergreen');
    expect(matches[0]?.confidence).toBe(0.99);
    expect(text.slice(matches[0]!.start, matches[0]!.end)).toBe('Evergreen');

    // Empty list produces no matches
    expect(detectPersons(text, { knownNames: [] })).toHaveLength(0);
  });

  it('validates isPlausibleName helper', () => {
    expect(isPlausibleName('Sarah Jenkins')).toBe(true);
    expect(isPlausibleName('Michael T. Rodriguez')).toBe(true);
    expect(isPlausibleName('Mike')).toBe(true);

    expect(isPlausibleName('TRANSCRIPT')).toBe(false); // all caps
    expect(isPlausibleName('END')).toBe(false); // all caps
    expect(isPlausibleName('PII-TEST-001')).toBe(false); // contains digits
    expect(isPlausibleName('Agent')).toBe(false); // role word
    expect(isPlausibleName('System')).toBe(false); // role word
    expect(isPlausibleName('Support')).toBe(false); // role word
    expect(isPlausibleName('One Two Three Four Five')).toBe(false); // too many tokens
  });

  it('handles empty string, whitespace-only, and large text safely', () => {
    expect(detectPersons('')).toEqual([]);
    expect(detectPersons('   \n\t  ')).toEqual([]);

    const largeNoNames = 'The quick brown fox jumps over the lazy dog. '.repeat(250);
    expect(detectPersons(largeNoNames)).toEqual([]);
  });
});
