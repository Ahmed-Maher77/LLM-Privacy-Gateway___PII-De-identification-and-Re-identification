import type { PIIMatch, PIIType, RegexDetectorOptions } from './types.js';

/**
 * Checks if a numeric string passes the Luhn checksum algorithm (Mod 10).
 * Standard for credit cards (Visa, MasterCard, Amex, Discover, etc.).
 */
export function isValidLuhn(val: string): boolean {
  const digits = val.replace(/\D/g, '');
  if (digits.length < 2) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    const char = digits[i];
    if (!char) continue;
    let digit = parseInt(char, 10);
    if (Number.isNaN(digit)) return false;

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/** True if the SSN could actually have been issued by the SSA. */
export function isIssuableSSN(val: string): boolean {
  const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(val.trim());
  if (!m) return false;
  const [, area, group, serial] = m;
  if (area === '000' || area === '666' || area!.startsWith('9')) return false;
  if (group === '00') return false;
  if (serial === '0000') return false;
  return true;
}

/** Matches a known issuer identification number prefix. */
export function hasCardBrandPrefix(digits: string): boolean {
  if (/^4/.test(digits)) return true;                     // Visa
  if (/^5[1-5]/.test(digits)) return true;                // MasterCard
  if (/^2(2[2-9][1-9]|[3-6]\d{2}|7[01]\d|720)/.test(digits)) return true; // MC 2-series
  if (/^3[47]/.test(digits)) return true;                 // Amex
  if (/^(6011|65|64[4-9])/.test(digits)) return true;     // Discover
  if (/^3(0[0-5]|[68])/.test(digits)) return true;        // Diners
  if (/^35(2[89]|[3-8]\d)/.test(digits)) return true;     // JCB
  return false;
}

/**
 * Validates whether a candidate phone string has a valid digit count
 * and is not an obvious date (e.g., YYYY-MM-DD).
 */
function isValidPhone(matchStr: string): boolean {
  // Reject ISO/hyphenated dates like 2024-05-12 or 1999-12-31
  if (/^\d{4}[-/]\d{2}[-/]\d{2}$/.test(matchStr)) {
    return false;
  }

  const digits = matchStr.replace(/\D/g, '');
  // Standard phone numbers have between 7 and 15 digits (ITU-T E.164)
  return digits.length >= 7 && digits.length <= 15;
}

/**
 * Trims common trailing punctuation attached to URLs or tokens at sentence boundaries.
 */
function trimTrailingPunctuation(str: string): { trimmed: string; removedCount: number } {
  let trimmed = str;
  let removedCount = 0;

  while (/[.,:;?!)>\]}\\'"]$/.test(trimmed)) {
    trimmed = trimmed.slice(0, -1);
    removedCount++;
  }

  return { trimmed, removedCount };
}

interface RegexRule {
  type: PIIType;
  regex: RegExp;
  confidence: number;
  validator?: (match: string, options?: RegexDetectorOptions) => boolean;
  /** Per-match confidence. Overrides `confidence` when present. */
  score?: (match: string) => number;
  trimTrailing?: boolean;
}

const STREET_SUFFIX =
  'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr' +
  '|Terrace|Ter|Court|Ct|Circle|Cir|Way|Place|Pl|Parkway|Pkwy|Highway|Hwy';

const US_STATE =
  'A[LKZR]|C[AOT]|D[CE]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]' +
  '|N[CDEHJMVY]|O[HKR]|PA|RI|S[CD]|T[NX]|UT|V[AT]|W[AIVY]';

const ADDRESS_PATTERN = new RegExp(
  String.raw`\b\d{1,6}\s+(?:[A-Z][A-Za-z.]*\s+){0,4}(?:${STREET_SUFFIX})\b\.?` +
    String.raw`(?:\s+(?:NW|NE|SW|SE|N|S|E|W)\b)?` +
    String.raw`(?:\s*,\s*[A-Z][A-Za-z.]*(?:\s+[A-Z][A-Za-z.]*)*)?` +
    String.raw`(?:\s*,\s*(?:${US_STATE})\s+\d{5}(?:-\d{4})?)?`,
  'g'
);

const REGEX_RULES: RegexRule[] = [
  // 1. Email (RFC 5322 pragmatic pattern with word boundaries)
  {
    type: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    confidence: 0.99,
  },

  // 2. Phone Numbers
  // Matches international (+20 100 123 4567, +1 555 123 4567, (+20) 100-123-4567),
  // standard US ((555) 123-4567, 555-123-4567), and local formats (01001234567).
  {
    type: 'PHONE',
    regex: /(?:(?:\(\+\d{1,3}\)|\+\d{1,3})[\s.-]?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?:[\s.-]?\d{1,4})?|\(\d{3}\)[\s.-]?\d{3}[\s.-]?\d{4}|\b\d{3}[-.]\d{3}[-.]\d{4}\b|\b01[0125]\d{8}\b)/g,
    confidence: 0.95,
    validator: (m) => isValidPhone(m),
    trimTrailing: true,
  },

  // 3. URLs (http, https, www)
  {
    type: 'URL',
    regex: /\b(?:https?:\/\/[^\s<>'"]+|www\.[A-Za-z0-9.-]+\.[A-Za-z]{2,}[^\s<>'"]*)/gi,
    confidence: 0.99,
    trimTrailing: true,
  },

  // 4. IPv4 Addresses (strictly 0-255 octets)
  {
    type: 'IP_ADDRESS',
    regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/g,
    confidence: 0.98,
  },

  // 5. Credit Card Numbers (13-19 digits, 4-4-4-4 or 4-6-5 groupings)
  {
    type: 'CREDIT_CARD',
    regex: /\b(?:\d{4}[ -]?){3}\d{4}\b|\b3[47]\d{2}[ -]?\d{6}[ -]?\d{5}\b/g,
    confidence: 0.85,
    validator: (m, options) => {
      const digits = m.replace(/\D/g, '');
      if (digits.length < 13 || digits.length > 19) return false;
      if (isValidLuhn(digits)) return true;
      // strict mode exists so the evaluation harness can measure Luhn-only behaviour
      if (options?.strictLuhn) return false;
      // Luhn-invalid but brand-prefixed AND grouped with separators -> still disclosive
      return hasCardBrandPrefix(digits) && /[ -]/.test(m);
    },
    score: (m) => (isValidLuhn(m) ? 0.98 : 0.85),
  },

  // 6. US Social Security Number (SSN)
  {
    type: 'SSN',
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    confidence: 0.9,
    score: (m) => (isIssuableSSN(m) ? 0.98 : 0.9),
  },

  // 7. Physical Address (Street, City, State ZIP)
  {
    type: 'ADDRESS',
    regex: ADDRESS_PATTERN,
    confidence: 0.9,
    trimTrailing: true,
  },
];

/**
 * Detects PII entities using deterministic regex rules.
 *
 * @param text The input text to process
 * @param options Regex detector options
 * @returns Array of normalized PII matches from deterministic rules
 */
export function detectWithRegex(
  text: string,
  options?: RegexDetectorOptions
): PIIMatch[] {
  if (!text || typeof text !== 'string') {
    return [];
  }

  const matches: PIIMatch[] = [];

  for (const rule of REGEX_RULES) {
    // Reset regex state for global regex
    rule.regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = rule.regex.exec(text)) !== null) {
      let rawVal = match[0];
      const start = match.index;
      let end = start + rawVal.length;

      if (rule.trimTrailing) {
        const { trimmed } = trimTrailingPunctuation(rawVal);
        rawVal = trimmed;
        end = start + rawVal.length;
      }

      if (rule.validator && !rule.validator(rawVal, options)) {
        continue;
      }

      // Exact substring safety guarantee
      const exactSubstring = text.slice(start, end);
      if (exactSubstring !== rawVal) {
        continue;
      }

      matches.push({
        type: rule.type,
        value: rawVal,
        start,
        end,
        method: 'regex',
        confidence: rule.score ? rule.score(rawVal) : rule.confidence,
      });
    }
  }

  return matches;
}
