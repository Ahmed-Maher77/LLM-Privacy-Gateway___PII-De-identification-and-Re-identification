import { describe, it, expect } from 'vitest';
import { maskPII, maskPIIWithMapping, unmaskPII } from '../src/pii/masker.js';
import type { PIIMatch } from '../src/pii/types.js';

describe('Masker Layer', () => {
  it('masks multiple PII matches with default format [TYPE]', () => {
    const text = 'My name is Ahmed and my email is ahmed@example.com';
    const matches: PIIMatch[] = [
      {
        type: 'PERSON',
        value: 'Ahmed',
        start: 11,
        end: 16,
        method: 'rule',
      },
      {
        type: 'EMAIL',
        value: 'ahmed@example.com',
        start: 33,
        end: 50,
        method: 'regex',
      },
    ];

    const masked = maskPII(text, matches);
    expect(masked).toBe('My name is [PERSON] and my email is [EMAIL]');
  });

  it('preserves exact spacing and punctuation surrounding masked tokens', () => {
    const text = 'Contact: <ahmed@example.com>, Tel: (+20) 100-123-4567!';
    const matches: PIIMatch[] = [
      {
        type: 'EMAIL',
        value: 'ahmed@example.com',
        start: 10,
        end: 27,
        method: 'regex',
      },
      {
        type: 'PHONE',
        value: '(+20) 100-123-4567',
        start: 35,
        end: 53,
        method: 'regex',
      },
    ];

    const masked = maskPII(text, matches);
    expect(masked).toBe('Contact: <[EMAIL]>, Tel: [PHONE]!');
  });

  it('supports custom formatMask callback', () => {
    const text = 'Call 555-123-4567';
    const matches: PIIMatch[] = [
      {
        type: 'PHONE',
        value: '555-123-4567',
        start: 5,
        end: 17,
        method: 'regex',
      },
    ];

    const masked = maskPII(text, matches, {
      formatMask: (m) => `***REDACTED_${m.type}***`,
    });
    expect(masked).toBe('Call ***REDACTED_PHONE***');
  });

  it('returns original string when matches array is empty', () => {
    const text = 'No PII here.';
    expect(maskPII(text, [])).toBe(text);
  });

  describe('Numbered Masking and Mapping Back (unmaskPII)', () => {
    it('numbers distinct entities with 1-based indexing per type', () => {
      const text = 'Emails: primary alice@work.com and backup bob@home.org.';
      const matches: PIIMatch[] = [
        {
          type: 'EMAIL',
          value: 'alice@work.com',
          start: 16,
          end: 30,
          method: 'regex',
        },
        {
          type: 'EMAIL',
          value: 'bob@home.org',
          start: 42,
          end: 54,
          method: 'regex',
        },
      ];

      const { maskedText, entityMap, entities } = maskPIIWithMapping(text, matches, {
        numbered: true,
      });

      expect(maskedText).toBe('Emails: primary [EMAIL_1] and backup [EMAIL_2].');
      expect(entityMap).toEqual({
        '[EMAIL_1]': 'alice@work.com',
        '[EMAIL_2]': 'bob@home.org',
      });
      expect(entities).toHaveLength(2);
      expect(entities[0]).toMatchObject({
        placeholder: '[EMAIL_1]',
        type: 'EMAIL',
        index: 1,
        value: 'alice@work.com',
        occurrences: 1,
      });

      // Unmasking / Mapping back
      const restored = unmaskPII(maskedText, entityMap);
      expect(restored).toBe(text);
    });

    it('reuses the same numbered placeholder for identical entity values (Coreference)', () => {
      const text = 'Sarah met with Sarah Jenkins and then Sarah called Sarah.';
      // Sarah at [0, 5], Sarah Jenkins at [15, 28], Sarah at [38, 43], Sarah at [51, 56]
      const matches: PIIMatch[] = [
        { type: 'PERSON', value: 'Sarah', start: 0, end: 5, method: 'rule' },
        { type: 'PERSON', value: 'Sarah Jenkins', start: 15, end: 28, method: 'rule' },
        { type: 'PERSON', value: 'Sarah', start: 38, end: 43, method: 'rule' },
        { type: 'PERSON', value: 'Sarah', start: 51, end: 56, method: 'rule' },
      ];

      const { maskedText, entityMap, entities } = maskPIIWithMapping(text, matches, {
        numbered: true,
        numberingStrategy: 'entity',
      });

      expect(maskedText).toBe('[PERSON_1] met with [PERSON_2] and then [PERSON_1] called [PERSON_1].');
      expect(entityMap).toEqual({
        '[PERSON_1]': 'Sarah',
        '[PERSON_2]': 'Sarah Jenkins',
      });

      const sarahEntry = entities.find((e) => e.placeholder === '[PERSON_1]');
      expect(sarahEntry?.occurrences).toBe(3);

      // Reversible unmasking
      const restored = unmaskPII(maskedText, entityMap);
      expect(restored).toBe(text);
    });

    it('assigns unique numbers per occurrence when numberingStrategy is occurrence', () => {
      const text = 'Sarah met Sarah';
      const matches: PIIMatch[] = [
        { type: 'PERSON', value: 'Sarah', start: 0, end: 5, method: 'rule' },
        { type: 'PERSON', value: 'Sarah', start: 10, end: 15, method: 'rule' },
      ];

      const { maskedText, entityMap } = maskPIIWithMapping(text, matches, {
        numbered: true,
        numberingStrategy: 'occurrence',
      });

      expect(maskedText).toBe('[PERSON_1] met [PERSON_2]');
      expect(entityMap['[PERSON_1]']).toBe('Sarah');
      expect(entityMap['[PERSON_2]']).toBe('Sarah');

      const restored = unmaskPII(maskedText, entityMap);
      expect(restored).toBe(text);
    });

    it('supports 0-based indexing when configured', () => {
      const text = 'Call 555-0001 or 555-0002';
      const matches: PIIMatch[] = [
        { type: 'PHONE', value: '555-0001', start: 5, end: 13, method: 'regex' },
        { type: 'PHONE', value: '555-0002', start: 17, end: 25, method: 'regex' },
      ];

      const masked = maskPII(text, matches, {
        numbered: true,
        indexBase: 0,
      });

      expect(masked).toBe('Call [PHONE_0] or [PHONE_1]');
    });

    it('accurately round-trips complex transcripts with multiple entity types', () => {
      const text = 'Agent Sarah (555-0100) assisted Mike (mike@test.com) at 123 Main St on 2023-10-01.';
      const matches: PIIMatch[] = [
        { type: 'PERSON', value: 'Sarah', start: 6, end: 11, method: 'rule' },
        { type: 'PHONE', value: '555-0100', start: 13, end: 21, method: 'regex' },
        { type: 'PERSON', value: 'Mike', start: 32, end: 36, method: 'rule' },
        { type: 'EMAIL', value: 'mike@test.com', start: 38, end: 51, method: 'regex' },
        { type: 'ADDRESS', value: '123 Main St', start: 56, end: 67, method: 'regex' },
        { type: 'DATE', value: '2023-10-01', start: 71, end: 81, method: 'winknlp' },
      ];

      const { maskedText, entityMap } = maskPIIWithMapping(text, matches, {
        numbered: true,
      });

      expect(maskedText).toBe(
        'Agent [PERSON_1] ([PHONE_1]) assisted [PERSON_2] ([EMAIL_1]) at [ADDRESS_1] on [DATE_1].'
      );

      const unmasked = unmaskPII(maskedText, entityMap);
      expect(unmasked).toBe(text);
    });
  });
});
