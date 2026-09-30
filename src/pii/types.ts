// Shared types for the PII pipeline

// The types this pipeline detects and masks. Everything else is left as is
export const ENTITY_TYPES = [
    "PERSON",
    "ORGANIZATION",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "DATE_TIME",
    "US_SSN",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];

export interface PIISpan {
    start: number; // The start index of the span in the original text
    end: number;
    type: EntityType;
    text: string;
    score?: number;
    source:
        | "predefined"
        | "dictionary"
        | "regex"
        | "ner"
        | "wink"
        | "repeat"; // Which layer found it (for debugging)
}

export interface RedactResult {
    text: string;
    spans: PIISpan[];
    metrics: DetectionMetrics;
}

export interface DetectionMetrics {
    layerTimingsMs: Record<string, number>;
    layerCounts: Record<string, number>;
}

export interface Word {
    text: string;
    start: number;
    end: number;
}

export interface Lists {
    given: Set<string>;
    surnames: Set<string>;
    places: Set<string>;
}

export interface JsonReportInput {
    inputPath: string;
    inputChars: number;
    totalMs: number;
    sanitizedPath: string;
    layerTimingsMs: Readonly<Record<string, number>>;
    layerCounts: Readonly<Record<string, number>>;
    spans: readonly PIISpan[];
}

export type PredefinedList = Partial<Record<EntityType, string[]>>;