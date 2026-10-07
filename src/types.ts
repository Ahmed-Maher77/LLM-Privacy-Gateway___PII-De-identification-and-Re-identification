export type PIIType =
    | "EMAIL"
    | "URL"
    | "DATE"
    | "TIME"
    | "PHONE"
    | "MONEY"
    | "IP_ADDRESS"
    | "PERSON"
    | "LOCATION"
    | "ORGANIZATION"
    | "MENTION";

export interface PIIMatch {
    type: PIIType;
    value: string;
    start: number;
    end: number;
    source?: string;
}

export type PIIMaskConfig = Partial<Record<PIIType, boolean>>;

export interface JsonReportInput {
    inputPath: string;
    inputChars: number;
    totalMs: number;
    sanitizedPath: string;
    spans: readonly PIIMatch[];
}
