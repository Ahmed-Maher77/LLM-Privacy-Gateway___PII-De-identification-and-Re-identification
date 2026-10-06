# WinkNLP PII Redaction Pipeline

A lightweight, high-performance Node.js & TypeScript pipeline for detecting and redacting Personally Identifiable Information (PII) using [`wink-nlp`](https://winkjs.org/wink-nlp/) and the [`wink-eng-lite-web-model`](https://www.npmjs.com/package/wink-eng-lite-web-model).

---

## Pipeline Architecture & Data Flow

The following diagram illustrates the primary layers and stages data passes through during detection, redaction, and reporting:

```mermaid
flowchart TD
    subgraph S1["1. Ingestion"]
        A["Raw Text Input"]
    end

    subgraph S2["2. Detection Layer"]
        B["Tokenization & Offset Indexing"]
        C["Entity Recognition & Policy Filtering"]
        B --> C
    end

    subgraph S3["3. Masking Layer"]
        D["Span Ordering & Overlap Resolution"]
        E["Categorical Replacement ([EMAIL], [PERSON], etc.)"]
        D --> E
    end

    subgraph S4["4. Output & Audit Layer"]
        F["Sanitized Document (.sanitized.txt)"]
        G["Audit Report (.json metrics)"]
    end

    A --> B
    C --> D
    E --> F
    E --> G
```

### Main Pipeline Layers

1. **Ingestion Layer**: Ingests unstructured plaintext documents, conversational logs, or transcripts.
2. **Detection Layer**:
   - **Tokenization & Offset Indexing**: Parses text into tokens and builds character offset maps in a single $O(N)$ pass using wink-nlp's span token index.
   - **Entity Recognition & Policy Filtering**: Extracts named entities and filters them against the active configuration flags.
3. **Masking Layer**:
   - **Span Ordering & Overlap Resolution**: Sorts entity matches ascending by offset and prunes overlapping spans to avoid corrupting text replacements.
   - **Categorical Replacement**: Sequentially substitutes sensitive spans with standard bracketed placeholders (e.g., `[EMAIL]`, `[DATE]`, `[PERSON]`).
4. **Output & Audit Layer**: Generates sanitized text output alongside execution telemetry and structured detection metadata.

---

## Supported Entity Types & Configuration

The detection engine supports configurable entity filtering via `PIIMaskConfig`:

| Entity Type | Description | Default Enabled | Placeholder |
|---|---|:---:|---|
| `EMAIL` | Email addresses | Yes | `[EMAIL]` |
| `URL` | Web links and domain references | Yes | `[URL]` |
| `DATE` | Calendar dates, days, and references | Yes | `[DATE]` |
| `PHONE` | International and local phone numbers | No | `[PHONE]` |
| `PERSON` | Individual names | No | `[PERSON]` |
| `LOCATION` | Cities, countries, addresses | No | `[LOCATION]` |
| `ORGANIZATION`| Company and institution names | No | `[ORGANIZATION]` |
| `MENTION` | Social media handles / @-mentions | No | `[MENTION]` |
| `TIME` | Timestamps and time expressions | No | `[TIME]` |
| `MONEY` | Currency values and monetary expressions | No | `[MONEY]` |
| `IP_ADDRESS` | IPv4 / IPv6 addresses | No | `[IP_ADDRESS]` |

---

## Project Structure

```
├── src/
│   ├── generate_reports/
│   │   ├── writeJsonReport.ts        # Exports structured JSON detection metrics
│   │   └── writeSanitizedReport.ts   # Writes redacted plaintext to reports/
│   ├── index.ts                      # CLI / pipeline runner entry point
│   ├── pii-masker.ts                 # Core detection and masking logic
│   └── types.ts                      # TypeScript interfaces and types
├── test/
│   └── pii-masker.test.ts            # Unit test suite (Node test runner via tsx)
├── test_data/
│   └── mockup_interview.txt          # Synthetic multi-format test transcript
├── .env.example                      # Template environment variables
├── .gitattributes                    # Cross-platform line ending normalization
├── .gitignore                        # Comprehensive ignore rules
├── package.json                      # Scripts and dependencies
└── tsconfig.json                     # TypeScript build configuration
```

---

## Programmatic API Usage

You can import and use the detection and masking functions directly in your application:

```typescript
import { detectPII, maskPII } from "./src/pii-masker";

const text = "Contact John Doe at john.doe@example.com before tomorrow.";

// 1. Detect PII with custom configuration
const matches = detectPII(text, {
  EMAIL: true,
  DATE: true,
  PERSON: true,
});

console.log(matches);
// Output:
// [
//   { type: 'PERSON', value: 'John Doe', start: 8, end: 16, source: 'wink-nlp' },
//   { type: 'EMAIL', value: 'john.doe@example.com', start: 20, end: 40, source: 'wink-nlp' },
//   { type: 'DATE', value: 'tomorrow', start: 48, end: 56, source: 'wink-nlp' }
// ]

// 2. Redact PII safely
const sanitized = maskPII(matches, text);
console.log(sanitized);
// "Contact [PERSON] at [EMAIL] before [DATE]."
```

---

## Getting Started

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher recommended)
- `npm` or `yarn`

### Installation

```bash
npm install
```

### Configuration

Copy the example environment file:

```bash
cp .env.example .env
```

### Running the Pipeline

Run the pipeline against the default synthetic test fixture (`test_data/mockup_interview.txt`):

```bash
npm run dev
```

Output files will be generated in the `reports/` folder:
- `reports/<filename>.sanitized.txt`: The redacted text file.
- `reports/<filename>__report.json`: Execution time, span counts, and detected span details.

### Running Tests

Execute the unit test suite:

```bash
npm test
```

### Building for Production

Compile TypeScript into JavaScript in the `dist/` directory:

```bash
npm run build
```

---

## Testing & Fixtures

The [`test_data/`](./test_data/) directory contains synthetic fixtures designed to evaluate entity recognition and redaction accuracy across various scenarios (emails, dates, phone numbers, international formats). All test data is purely synthetic and contains no confidential or real personal information.

---

## License

[ISC](./package.json)
