import { describe, it, expect } from 'vitest';
import {
  detectWithRegex,
  isValidLuhn,
  isIssuableSSN,
  hasCardBrandPrefix,
} from '../src/pii/regex-detector.js';

describe('Regex Detector', () => {
  it('detects standard and international email formats', () => {
    const text = 'Contact john.doe@company.co.uk or ahmed@example.com.';
    const matches = detectWithRegex(text);

    const emails = matches.filter((m) => m.type === 'EMAIL');
    expect(emails).toHaveLength(2);
    expect(emails[0]?.value).toBe('john.doe@company.co.uk');
    expect(emails[1]?.value).toBe('ahmed@example.com');

    for (const match of emails) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('detects international and domestic phone numbers', () => {
    const samples = [
      { text: 'Call me at +20 100 123 4567.', expected: '+20 100 123 4567' },
      { text: 'US office: +1 555 123 4567.', expected: '+1 555 123 4567' },
      { text: 'Mobile: 01001234567.', expected: '01001234567' },
      { text: 'Phone: (+20) 100-123-4567.', expected: '(+20) 100-123-4567' },
      { text: 'Direct: (555) 123-4567.', expected: '(555) 123-4567' },
      { text: 'Direct line: 555-123-4567.', expected: '555-123-4567' },
    ];

    for (const sample of samples) {
      const matches = detectWithRegex(sample.text);
      const phoneMatch = matches.find((m) => m.type === 'PHONE');
      expect(phoneMatch).toBeDefined();
      expect(phoneMatch?.value).toBe(sample.expected);
      expect(sample.text.slice(phoneMatch!.start, phoneMatch!.end)).toBe(sample.expected);
    }
  });

  it('does not falsely detect dates as phone numbers', () => {
    const text = 'The release date was 2024-05-12 and 1999-12-31.';
    const matches = detectWithRegex(text);
    const phones = matches.filter((m) => m.type === 'PHONE');
    expect(phones).toHaveLength(0);
  });

  it('detects URLs and trims trailing sentence punctuation', () => {
    const text = 'Visit https://example.com, http://company.com/profile, or www.example.com.';
    const matches = detectWithRegex(text);
    const urls = matches.filter((m) => m.type === 'URL');

    expect(urls).toHaveLength(3);
    expect(urls[0]?.value).toBe('https://example.com');
    expect(urls[1]?.value).toBe('http://company.com/profile');
    expect(urls[2]?.value).toBe('www.example.com');

    for (const match of urls) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('detects valid IPv4 addresses and rejects invalid octets', () => {
    const text = 'Server IPs: 192.168.1.10 and 8.8.8.8. Invalid: 999.999.999.999.';
    const matches = detectWithRegex(text);
    const ips = matches.filter((m) => m.type === 'IP_ADDRESS');

    expect(ips).toHaveLength(2);
    expect(ips[0]?.value).toBe('192.168.1.10');
    expect(ips[1]?.value).toBe('8.8.8.8');

    for (const match of ips) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('detects credit cards by shape and brand prefix, using Luhn for confidence', () => {
    // 4111 2222 3333 4321 is Luhn-invalid, but brand-prefixed (Visa) and spaced
    const text =
      'Cards: 4111 2222 3333 4321 and 4532-0150-0000-0007. Non-cards: 1111-2222-3333-4445 and 1234567890123456.';
    const matches = detectWithRegex(text);
    const cards = matches.filter((m) => m.type === 'CREDIT_CARD');

    expect(cards).toHaveLength(2);

    const luhnInvalidVisa = cards.find((m) => m.value === '4111 2222 3333 4321');
    const luhnValidVisa = cards.find((m) => m.value === '4532-0150-0000-0007');

    expect(luhnInvalidVisa).toBeDefined();
    expect(luhnInvalidVisa?.confidence).toBe(0.85);

    expect(luhnValidVisa).toBeDefined();
    expect(luhnValidVisa?.confidence).toBe(0.98);

    for (const match of cards) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }

    // With strictLuhn: true, Luhn-invalid card must NOT be detected
    const strictMatches = detectWithRegex(text, { strictLuhn: true });
    const strictCards = strictMatches.filter((m) => m.type === 'CREDIT_CARD');
    expect(strictCards).toHaveLength(1);
    expect(strictCards[0]?.value).toBe('4532-0150-0000-0007');
  });

  it('validates hasCardBrandPrefix correctly', () => {
    expect(hasCardBrandPrefix('4111222233334321')).toBe(true); // Visa
    expect(hasCardBrandPrefix('5100123456789012')).toBe(true); // MC
    expect(hasCardBrandPrefix('370012345678901')).toBe(true); // Amex
    expect(hasCardBrandPrefix('6011123456789012')).toBe(true); // Discover
    expect(hasCardBrandPrefix('1111222233334445')).toBe(false); // Unknown brand
  });

  it('detects all SSN-shaped numbers regardless of issuance validity, scoring valid higher', () => {
    const text = 'Issuable: 123-45-6789. Non-issuable: 000-12-3456 and 666-12-3456. Phone: 555-987-6543.';
    const matches = detectWithRegex(text);
    const ssns = matches.filter((m) => m.type === 'SSN');

    expect(ssns).toHaveLength(3);

    const validSsn = ssns.find((m) => m.value === '123-45-6789');
    const placeholderSsn = ssns.find((m) => m.value === '000-12-3456');
    const reservedSsn = ssns.find((m) => m.value === '666-12-3456');

    expect(validSsn).toBeDefined();
    expect(validSsn?.confidence).toBe(0.98);

    expect(placeholderSsn).toBeDefined();
    expect(placeholderSsn?.confidence).toBe(0.9);

    expect(reservedSsn).toBeDefined();
    expect(reservedSsn?.confidence).toBe(0.9);

    // 555-987-6543 (phone) must NOT be detected as SSN
    expect(ssns.some((m) => m.value.includes('555-987'))).toBe(false);

    for (const match of ssns) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }
  });

  it('validates isIssuableSSN correctly', () => {
    expect(isIssuableSSN('123-45-6789')).toBe(true);
    expect(isIssuableSSN('000-12-3456')).toBe(false);
    expect(isIssuableSSN('666-12-3456')).toBe(false);
    expect(isIssuableSSN('900-12-3456')).toBe(false);
    expect(isIssuableSSN('123-00-6789')).toBe(false);
    expect(isIssuableSSN('123-45-0000')).toBe(false);
  });

  it('detects physical addresses accurately and ignores non-address numbers', () => {
    const cases = [
      {
        input: 'It should be 742 Evergreen Terrace, Springfield, OR 97403.',
        expected: '742 Evergreen Terrace, Springfield, OR 97403',
      },
      {
        input: 'Ship to 1600 Pennsylvania Avenue NW, Washington, DC 20500.',
        expected: '1600 Pennsylvania Avenue NW, Washington, DC 20500',
      },
      {
        input: 'Office at 350 Fifth Ave, New York, NY 10118.',
        expected: '350 Fifth Ave, New York, NY 10118',
      },
      {
        input: 'Apt at 12 Baker St, London.',
        expected: '12 Baker St, London',
      },
      {
        input: 'Order 4321 was shipped.',
        expected: null,
      },
      {
        input: 'I walked 5 Miles today.',
        expected: null,
      },
    ];

    for (const { input, expected } of cases) {
      const matches = detectWithRegex(input);
      const addressMatches = matches.filter((m) => m.type === 'ADDRESS');

      if (expected) {
        expect(addressMatches).toHaveLength(1);
        expect(addressMatches[0]?.value).toBe(expected);
        expect(input.slice(addressMatches[0]!.start, addressMatches[0]!.end)).toBe(expected);
      } else {
        expect(addressMatches).toHaveLength(0);
      }
    }
  });
});
