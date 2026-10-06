import type { PIIConfig, PIIType } from './types.js';

/**
 * Default configuration for PII detection.
 * Standard sensitive identifiers (email, phone, credit card, ip, person, etc.) are enabled.
 * Generic dates, times, and mentions are disabled by default unless explicitly requested.
 */
export const DEFAULT_PII_CONFIG: Required<PIIConfig> = {
  person: true,
  personStrategy: 'anchored',
  knownNames: [],
  knownLocations: [],
  knownOrganizations: [],
  email: true,
  phone: true,
  url: true,
  ipAddress: true,
  creditCard: true,
  strictLuhn: false,
  ssn: true,
  address: true,
  location: false,
  organization: false,
  date: false,
  time: false,
  mention: false,
  misc: false,
  enableWinkNLP: true,
  enableRegex: true,
};

/**
 * Resolves user config against defaults.
 */
export function resolveConfig(config?: Partial<PIIConfig>): Required<PIIConfig> {
  return {
    ...DEFAULT_PII_CONFIG,
    ...(config ?? {}),
  };
}

/**
 * Checks whether a given PIIType is enabled under the resolved config.
 */
export function isTypeEnabled(type: PIIType, config: Required<PIIConfig>): boolean {
  switch (type) {
    case 'PERSON':
      return config.person;
    case 'EMAIL':
      return config.email;
    case 'PHONE':
      return config.phone;
    case 'URL':
      return config.url;
    case 'IP_ADDRESS':
      return config.ipAddress;
    case 'CREDIT_CARD':
      return config.creditCard;
    case 'SSN':
      return config.ssn;
    case 'ADDRESS':
      return config.address;
    case 'LOCATION':
      return config.location;
    case 'ORGANIZATION':
      return config.organization;
    case 'DATE':
      return config.date;
    case 'TIME':
      return config.time;
    case 'MENTION':
      return config.mention;
    case 'MISC':
      return config.misc;
    default:
      return false;
  }
}
