import { describe, it, expect } from 'vitest';
import { detectPII } from '../src/pii/detector.js';
import { maskPII } from '../src/pii/masker.js';

describe('Central PII Detector (detectPII)', () => {
  it('detects basic email, phone, and url entities', () => {
    const text1 = 'Contact me at ahmed@example.com.';
    const matches1 = detectPII(text1);
    expect(matches1).toHaveLength(1);
    expect(matches1[0]?.type).toBe('EMAIL');
    expect(matches1[0]?.value).toBe('ahmed@example.com');
    expect(text1.slice(matches1[0]!.start, matches1[0]!.end)).toBe('ahmed@example.com');

    const text2 = 'Call me at +20 100 123 4567.';
    const matches2 = detectPII(text2);
    expect(matches2).toHaveLength(1);
    expect(matches2[0]?.type).toBe('PHONE');
    expect(matches2[0]?.value).toBe('+20 100 123 4567');
    expect(text2.slice(matches2[0]!.start, matches2[0]!.end)).toBe('+20 100 123 4567');

    const text3 = 'Visit https://example.com.';
    const matches3 = detectPII(text3);
    expect(matches3).toHaveLength(1);
    expect(matches3[0]?.type).toBe('URL');
    expect(matches3[0]?.value).toBe('https://example.com');
    expect(text3.slice(matches3[0]!.start, matches3[0]!.end)).toBe('https://example.com');
  });

  it('detects multiple PII types in a single passage', () => {
    const text =
      'My name is Ahmed Maher. My email is ahmed@example.com and my phone is +20 100 123 4567.';
    const matches = detectPII(text);

    // Expect email and phone, plus person (via Wink POS PROPN heuristic)
    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    const phoneMatch = matches.find((m) => m.type === 'PHONE');
    const personMatch = matches.find((m) => m.type === 'PERSON');

    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');

    expect(phoneMatch).toBeDefined();
    expect(phoneMatch?.value).toBe('+20 100 123 4567');

    expect(personMatch).toBeDefined();
    expect(personMatch?.value).toBe('Ahmed Maher');

    for (const match of matches) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('handles mixed sentences with single PII correctly', () => {
    const text =
      'Hello Ahmed, this is a normal sentence with no sensitive information except your email ahmed@example.com.';
    const matches = detectPII(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(text.slice(emailMatch!.start, emailMatch!.end)).toBe('ahmed@example.com');
  });

  it('handles repeated PII in the same text without offset corruption', () => {
    const text = 'Ahmed contacted Ahmed using ahmed@example.com.';
    const matches = detectPII(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch?.value).toBe('ahmed@example.com');

    // All matches must satisfy exact substring slice
    for (const match of matches) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('handles punctuation around entities correctly', () => {
    const text = 'Email: <ahmed@example.com>. Phone: (+20) 100-123-4567.';
    const matches = detectPII(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    const phoneMatch = matches.find((m) => m.type === 'PHONE');

    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(phoneMatch?.value).toBe('(+20) 100-123-4567');

    for (const match of matches) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('handles Unicode and Arabic text with correct indexing', () => {
    const text = 'اسمي أحمد والبريد الإلكتروني ahmed@example.com';
    const matches = detectPII(text);

    const emailMatch = matches.find((m) => m.type === 'EMAIL');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.value).toBe('ahmed@example.com');
    expect(text.slice(emailMatch!.start, emailMatch!.end)).toBe('ahmed@example.com');

    const masked = maskPII(text, matches);
    expect(masked).toBe('اسمي أحمد والبريد الإلكتروني [EMAIL]');
  });

  it('respects configuration flags (enabling/disabling categories)', () => {
    const text = 'Reach ahmed@example.com or call +20 100 123 4567.';

    // Disable email
    const noEmailMatches = detectPII(text, { email: false });
    expect(noEmailMatches.some((m) => m.type === 'EMAIL')).toBe(false);
    expect(noEmailMatches.some((m) => m.type === 'PHONE')).toBe(true);

    // Disable phone
    const noPhoneMatches = detectPII(text, { phone: false });
    expect(noPhoneMatches.some((m) => m.type === 'EMAIL')).toBe(true);
    expect(noPhoneMatches.some((m) => m.type === 'PHONE')).toBe(false);
  });

  it('enables DATE detection only when explicitly configured', () => {
    const text = 'Meeting on April 1, 1976 with tim@example.com.';

    // By default, date is false
    const defaultMatches = detectPII(text);
    expect(defaultMatches.some((m) => m.type === 'DATE')).toBe(false);
    expect(defaultMatches.some((m) => m.type === 'EMAIL')).toBe(true);

    // With date: true
    const withDateMatches = detectPII(text, { date: true });
    expect(withDateMatches.some((m) => m.type === 'DATE')).toBe(true);
  });

  it('supports disabling specific engine (enableWinkNLP vs enableRegex)', () => {
    const text = 'Server IP: 192.168.1.10, Email: ahmed@example.com.';

    // Regex only (IP and Email detected by regex)
    const regexOnly = detectPII(text, { enableWinkNLP: false });
    expect(regexOnly.some((m) => m.type === 'IP_ADDRESS')).toBe(true);
    expect(regexOnly.every((m) => m.method === 'regex')).toBe(true);

    // WinkNLP only (IP is not detected by WinkNLP)
    const winkOnly = detectPII(text, { enableRegex: false });
    expect(winkOnly.some((m) => m.type === 'IP_ADDRESS')).toBe(false);
    expect(winkOnly.some((m) => m.type === 'EMAIL')).toBe(true);
    expect(winkOnly.every((m) => m.method === 'winknlp')).toBe(true);
  });

  it('supports strictLuhn flag for credit card detection', () => {
    // 4111 2222 3333 4321 has valid brand prefix (Visa) but invalid Luhn checksum
    const text = 'Card: 4111 2222 3333 4321';

    // Default: shape-first masks it
    const defaultMatches = detectPII(text);
    expect(defaultMatches.some((m) => m.type === 'CREDIT_CARD')).toBe(true);

    // strictLuhn: true drops invalid Luhn numbers
    const strictMatches = detectPII(text, { strictLuhn: true });
    expect(strictMatches.some((m) => m.type === 'CREDIT_CARD')).toBe(false);
  });
});
