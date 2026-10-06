/**
 * Supported PII and entity categories.
 */
export type PIIType =
  | 'PERSON'
  | 'EMAIL'
  | 'PHONE'
  | 'URL'
  | 'IP_ADDRESS'
  | 'CREDIT_CARD'
  | 'SSN'
  | 'ADDRESS'
  | 'ORGANIZATION'
  | 'LOCATION'
  | 'DATE'
  | 'TIME'
  | 'MENTION'
  | 'MISC';

/**
 * Detection method provenance.
 */
export type DetectionMethod = 'winknlp' | 'regex' | 'rule';

/**
 * Normalized PII match representation.
 */
export interface PIIMatch {
  type: PIIType;
  value: string;
  start: number;
  end: number;
  method: DetectionMethod;
  confidence?: number;
  /** Assigned placeholder token when numbered masking is applied (e.g. "[PERSON_1]") */
  placeholder?: string;
}

export type PersonStrategy = 'off' | 'anchored' | 'propn';

/**
 * Configuration options to control which PII types and engines are active.
 */
export interface PIIConfig {
  person?: boolean;
  personStrategy?: PersonStrategy;
  knownNames?: string[];
  knownLocations?: string[];
  knownOrganizations?: string[];
  email?: boolean;
  phone?: boolean;
  url?: boolean;
  ipAddress?: boolean;
  creditCard?: boolean;
  strictLuhn?: boolean;
  ssn?: boolean;
  address?: boolean;
  location?: boolean;
  organization?: boolean;
  date?: boolean;
  time?: boolean;
  mention?: boolean;
  misc?: boolean;
  enableWinkNLP?: boolean;
  enableRegex?: boolean;
}

/**
 * Options for the Person detector.
 */
export interface PersonDetectorOptions {
  knownNames?: string[];
}

/**
 * Options for the WinkNLP detector.
 */
export interface WinkDetectorOptions {
  extractDates?: boolean;
  extractTimes?: boolean;
  extractMentions?: boolean;
  /**
   * Experimental heuristic: extract sequences of consecutive PROPN (Proper Noun) tokens as PERSON.
   * Useful for evaluating WinkNLP's POS capabilities vs true NER.
   */
  extractProperNounsAsPerson?: boolean;
}

/**
 * Options for the regex detector.
 */
export interface RegexDetectorOptions {
  strictLuhn?: boolean;
}

/**
 * Strategy for assigning numbers to entities:
 * - 'entity': Identical values share the same numbered token (coreference-aware pseudonymization).
 * - 'occurrence': Every occurrence receives a new sequential number.
 */
export type NumberingStrategy = 'entity' | 'occurrence';

/**
 * Entry in the entity mapping table for de-anonymization / mapping back.
 */
export interface EntityMappingEntry {
  placeholder: string;
  type: PIIType;
  index: number;
  value: string;
  occurrences: number;
}

/**
 * Mapping dictionary from placeholder (e.g. "[PERSON_1]") to original plaintext value.
 */
export type EntityMap = Record<string, string>;

/**
 * Structured result of masking with entity mapping.
 */
export interface MaskResult {
  maskedText: string;
  entityMap: EntityMap;
  entities: EntityMappingEntry[];
}

/**
 * Masking options.
 */
export interface MaskOptions {
  /**
   * Whether to number entities (e.g., [PERSON_1], [EMAIL_1]) instead of generic [PERSON].
   * Default: false
   */
  numbered?: boolean;
  /**
   * Index base when numbered is true (e.g. 1 for [PERSON_1], 0 for [PERSON_0]).
   * Default: 1
   */
  indexBase?: number;
  /**
   * Strategy for numbering:
   * - 'entity': Identical values share the same numbered token (coreference-aware).
   * - 'occurrence': Every occurrence receives a new sequential number.
   * Default: 'entity'
   */
  numberingStrategy?: NumberingStrategy;
  /**
   * Custom format function: receives match and the default placeholder token.
   * Default: `placeholder ?? `[${match.type}]``
   */
  formatMask?: (match: PIIMatch, placeholder?: string) => string;
}
