import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from 'vitest';
import { detectPII } from '../src/pii/detector.js';
import { maskPII, maskPIIWithMapping, unmaskPII } from '../src/pii/masker.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const EXPECTED_MASKED_OUTPUT = `Test Case ID: PII-TEST-001
Date: [DATE]
Source: Customer Support Chat Log

[START OF TRANSCRIPT]

Agent (System): Thank you for contacting SecureBank Support. My name is [PERSON]. How can I help you today?

User: Hi [PERSON]. I’m having trouble logging in. My name is [PERSON], but my account might be under [PERSON].

Agent: I can help with that, Mr. [PERSON]. Can you please verify your identity? I have your date of birth listed here as [DATE].

User: Yes, that’s correct. My social security number is [SSN] if you need that.

Agent: Thank you. I see the account associated with email [EMAIL]. Is that correct?

User: Yes, but please send the reset link to my work email instead: [EMAIL].

Agent: Got it. I’ve updated the contact preference. Now, can you confirm the billing address on file?
User: It should be [ADDRESS].

Agent: Perfect. And the phone number we have on file is [PHONE].
User: Actually, my cell is better. It’s [PHONE].

Agent: Updated. For security purposes, can you confirm the last four digits of your card?
User: Sure, it’s a Visa ending in 4321. The full number is [CREDIT_CARD].

Agent: Thank you. I’ve unlocked your account. Is there anything else?
User: No, that’s all. Thanks, [PERSON].

Agent: You’re welcome. Have a great day.

[END OF TRANSCRIPT]`;

describe('Sample Regression Test (Section 2 Verification)', () => {
  const samplePath = path.resolve(__dirname, '../samples/large_sample.txt');
  const rawText = fs.readFileSync(samplePath, 'utf-8');
  // Normalize CRLF to LF for cross-platform comparison
  const text = rawText.replace(/\r\n/g, '\n');

  it('detects exactly 15 entities and matches section 2 target counts', () => {
    const matches = detectPII(text, { date: true });

    expect(matches).toHaveLength(15);

    // Verify offset invariant on every match
    for (const match of matches) {
      expect(text.slice(match.start, match.end)).toBe(match.value);
    }

    // Counts by type
    const counts: Record<string, number> = {};
    for (const m of matches) {
      counts[m.type] = (counts[m.type] ?? 0) + 1;
    }

    expect(counts['PERSON']).toBe(6);
    expect(counts['DATE']).toBe(2);
    expect(counts['SSN']).toBe(1);
    expect(counts['EMAIL']).toBe(2);
    expect(counts['ADDRESS']).toBe(1);
    expect(counts['PHONE']).toBe(2);
    expect(counts['CREDIT_CARD']).toBe(1);
  });

  it('masks the text matching Section 2 target output verbatim', () => {
    const matches = detectPII(text, { date: true });
    const masked = maskPII(text, matches);

    expect(masked.trim()).toBe(EXPECTED_MASKED_OUTPUT.trim());
  });

  it('preserves non-PII terms without false positive masking', () => {
    const matches = detectPII(text, { date: true });
    const masked = maskPII(text, matches);

    const preservedTerms = [
      'Test Case ID',
      'PII-TEST-001',
      'Source',
      'Customer Support Chat Log',
      '[START OF TRANSCRIPT]',
      '[END OF TRANSCRIPT]',
      'Agent',
      'System',
      'SecureBank Support',
      'Perfect',
      'Visa',
      '4321',
      'today',
    ];

    for (const term of preservedTerms) {
      expect(masked).toContain(term);
    }
  });

  it('masks with numbered tokens and successfully unmasks back to original text verbatim', () => {
    const matches = detectPII(text, { date: true });
    const { maskedText, entityMap, entities } = maskPIIWithMapping(text, matches, {
      numbered: true,
      indexBase: 1,
      numberingStrategy: 'entity',
    });

    // Contains numbered tokens
    expect(maskedText).toContain('[PERSON_1]');
    expect(maskedText).toContain('[DATE_1]');
    expect(maskedText).toContain('[EMAIL_1]');
    expect(maskedText).toContain('[SSN_1]');
    expect(maskedText).toContain('[ADDRESS_1]');
    expect(maskedText).toContain('[PHONE_1]');
    expect(maskedText).toContain('[CREDIT_CARD_1]');

    // Sarah appears twice in the transcript and shares [PERSON_2]
    const sarahEntry = entities.find((e) => e.value === 'Sarah');
    expect(sarahEntry?.occurrences).toBe(2);

    // Unmasking back must reproduce the original text verbatim
    const unmasked = unmaskPII(maskedText, entityMap);
    expect(unmasked).toBe(text);
  });
});
