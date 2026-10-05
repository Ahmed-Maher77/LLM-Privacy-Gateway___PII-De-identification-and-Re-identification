# WinkNLP PII Redaction Pipeline

A lightweight Node.js/TypeScript pipeline for identifying and redacting Personally Identifiable Information (PII) using [`wink-nlp`](https://winkjs.org/wink-nlp/) and the [`wink-eng-lite-web-model`](https://www.npmjs.com/package/wink-eng-lite-web-model).

## Features

- **Entity Recognition**: Detects PII entities including:
  - Emails
  - URLs & Mentions
  - Dates & Times
  - Phone Numbers
  - Persons, Locations & Organizations
- **Automated Masking**: Replaces detected sensitive entities with clear categorical placeholders (e.g., `[EMAIL]`, `[DATE]`).
- **Reporting**: Generates execution metrics and detection logs in JSON and sanitized text formats.

## Getting Started

### Prerequisites

- Node.js (v18+ recommended)
- npm or yarn

### Installation

```bash
npm install
```

### Configuration

Copy the example environment configuration:

```bash
cp .env.example .env
```

### Running the Pipeline

Run the pipeline against the default synthetic test fixture:

```bash
npm run dev
```

Sanitized output and analysis reports will be generated in the `reports/` directory.

## Testing & Fixtures

The `test_data/` directory contains synthetic test cases designed to evaluate entity recognition and redaction accuracy across various scenarios. All test cases use synthetic/mock data.

## License

ISC
