// Layer 2 — regex => fixed-format values, independent of any model (cards, IBANs, passports, driver's licences, phone numbers, dates)


import type { EntityType, PIISpan } from "../types";

interface Rule {
  type: EntityType;
  pattern: RegExp;
  group?: number;                 // Capture group holding the value (default: the whole match) => ex: instead of "passport number is 987654321" --> "987654321"
  valid?: (value: string) => boolean;
}

// ======== Check the Luhn checksum for credit card numbers =========
function luhnValid(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = Number(digits[digits.length - 1 - i]);
    if (i % 2 === 1 && (d *= 2) > 9) d -= 9;
    sum += d;
  }
  return sum % 10 === 0;
}

// ======== Check the IBAN checksum using the mod-97 algorithm =========
function ibanValid(value: string): boolean {
  const compact = value.replace(/\s+/g, "").toUpperCase();
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    for (const digit of /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55)) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder === 1;
}

const MONTH = "(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)";

// After a keyword: optional "number"/"no."/"#", then optional "is"/":"/"-".
const KEYWORD_TAIL = String.raw`(?:\s+(?:number|no\.?|num|#))?\s*(?:is\s+|[:#-]\s*)?`;

const RULES: Rule[] = [
  { type: "EMAIL_ADDRESS", pattern: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g },

  // 13–19 digits, optionally grouped by spaces or dashes
  { type: "CREDIT_CARD", pattern: /(?<![\d-])\d{4}(?:[ -]?\d{2,4}){2,4}(?![\d-])/g, valid: (v) => v.replace(/\D/g, "").length >= 13 && luhnValid(v) },

  { type: "IBAN_CODE", pattern: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g, valid: ibanValid },

  { type: "US_SSN", pattern: /(?<![\d-])\d{3}-\d{2}-\d{4}(?![\d-])/g },
  { type: "US_SSN", pattern: new RegExp(String.raw`\b(?:ssn|social\s+security)${KEYWORD_TAIL}(\d{3}[ -]?\d{2}[ -]?\d{4})\b`, "gi"), group: 1 },

  { type: "US_PASSPORT", pattern: new RegExp(String.raw`\bpassport${KEYWORD_TAIL}([A-Z0-9]{6,9})\b`, "gi"), group: 1, valid: (v) => /\d/.test(v) },

  {
    type: "US_DRIVER_LICENSE",
    pattern: new RegExp(String.raw`\b(?:driver'?s?\s+licen[cs]e|driving\s+licen[cs]e|DL)${KEYWORD_TAIL}([A-Z0-9][A-Z0-9-]{4,19})\b`, "gi"),
    group: 1,
    valid: (v) => /\d/.test(v),
  },

  // +1 (617) 555-0142, 617-555-0142, 617.555.0142, +44 20 7946 0958
  { type: "PHONE_NUMBER", pattern: /(?<![\w+.-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4}(?![\w-]|[ .]\d)/g },

  // 03/14/1985, 14.03.1985, 1985-03-14, and card expiry 08/27
  { type: "DATE_TIME", pattern: /\b(?:\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}|\d{4}-\d{2}-\d{2}|(?:0[1-9]|1[0-2])\/\d{2})\b(?![/.-]\d)/g },
  
  // March 14, 1985 / March 14th / 14 March 1985 / March 1985
  {
    type: "DATE_TIME",
    pattern: new RegExp(String.raw`\b(?:${MONTH}\.?\s+\d{1,2}(?:st|nd|rd|th)?(?:,?\s+\d{4})?|\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?${MONTH}\.?(?:,?\s+\d{4})?|${MONTH}\.?\s+\d{4})\b`, "gi"),
  },
];

export function detectRegex(text: string): PIISpan[] {
  const spans: PIISpan[] = [];
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.pattern)) {
      const value = m[rule.group ?? 0];
      if (!value || (rule.valid && !rule.valid(value))) continue;
      const start = m.index + (rule.group ? m[0].lastIndexOf(value) : 0);
      spans.push({ start, end: start + value.length, type: rule.type, text: value, source: "regex" });
    }
  }
  return spans;
}
