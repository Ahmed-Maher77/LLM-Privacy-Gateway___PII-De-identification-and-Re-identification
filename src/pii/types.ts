// Shared types for the PII pipeline

import type {
    PreTrainedModel,
    PreTrainedTokenizer,
    Tensor,
} from "@huggingface/transformers" with { "resolution-mode": "import" };

// The types this pipeline detects and masks. Everything else is left as is
export const ENTITY_TYPES = ["PERSON", "ORGANIZATION"] as const;

export type EntityType = (typeof ENTITY_TYPES)[number];

// =============== PII Span/Entity Type ===============
export interface PIISpan {
    start: number; // The start index of the span in the original text
    end: number;
    type: EntityType;
    text: string;
    score?: number;
    source: "predefined" | "ner" | "repeat"; // Which layer found it (for debugging)
}

// ============== Redaction Result ===============
export interface RedactResult {
    text: string;
    spans: PIISpan[];
    metrics: DetectionMetrics;
}

// ============= Detection Metrics ===============
export interface DetectionMetrics {
    layerTimingsMs: Record<string, number>;
    layerCounts: Record<string, number>;
}

// ============= NER Model Types =============
export interface NerModel {
    revision: string; // Hugging Face commit, so every fetch gets the same files
    files: { from: string; to?: string; sha256: string }[];
    person: string; // every other label is ignored
}

export interface Loaded {
    tokenizer: PreTrainedTokenizer;
    model: PreTrainedModel;
    makeTensor: (data: BigInt64Array) => Tensor;
    cls: number;
    sep: number;
    id2label: Record<number, string>;
    person: string;
}

export interface Piece {
    start: number;
    end: number;
    ids: number[];
    label?: string;
    score?: number;
    edge?: number; // sub-tokens to the nearer cut edge of the window it was labelled in
}

export interface Window {
    pieces: Piece[];
    cutStart: boolean;
    cutEnd: boolean;
}

// ============ Pre-defined List Types =============
export interface Rule {
    type: EntityType;
    pattern: RegExp;
    part?: boolean;               // a part of an entry: skipped if it is on the undesired list
    lowercaseLinesOnly?: boolean; // speech-to-text: a lowercase part counts only on a line with no capitals
}

export interface Lists {
    desired: Rule[];
    undesired: Set<string>;
}

export interface ListFile {
    json: unknown;
    file: string;
}


// =========== JSON Report Input Type =============
export interface JsonReportInput {
    inputPath: string;
    inputChars: number;
    totalMs: number;
    sanitizedPath: string;
    layerTimingsMs: Readonly<Record<string, number>>;
    layerCounts: Readonly<Record<string, number>>;
    spans: readonly PIISpan[];
}