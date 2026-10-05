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

export interface PIIMaskConfig {
    EMAIL?: boolean;
    URL?: boolean;
    DATE?: boolean;
    MONEY?: boolean;
    TIME?: boolean;
    PHONE?: boolean;
    IP_ADDRESS?: boolean;
    PERSON?: boolean;
    LOCATION?: boolean;
    ORGANIZATION?: boolean;
    MENTION?: boolean;
}

export interface JsonReportInput {
    inputPath: string;
    inputChars: number;
    totalMs: number;
    sanitizedPath: string;
    spans: readonly PIIMatch[];
}
