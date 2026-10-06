# AI Agent Guidelines & Operating Manual

> **CRITICAL DIRECTIVE FOR ALL AI AGENTS**:
> 1. **DO NOT** scan or read the entire codebase on every task. Consult [PROJECT_INDEX.md](PROJECT_INDEX.md) first as your primary index and architectural guide.
> 2. **MANDATORY MAINTENANCE**: Whenever you make **ANY** modification to this codebase (adding/modifying detectors, altering regex patterns, updating entity policies, creating pipeline stages, adding tests, or changing configuration), you **MUST UPDATE [PROJECT_INDEX.md](PROJECT_INDEX.md)** to reflect your changes before completing your task.

---

## 1. Primary Operating Protocol

When assigned a task in this repository:
1. **Consult Index First**: Read [PROJECT_INDEX.md](PROJECT_INDEX.md) to locate the relevant modules, data structures, and pipeline stages rather than doing broad directory/file scans.
2. **Adhere to Core Invariants**: Keep all 5 foundational invariants intact (see Section 2 below).
3. **Execute Unit Tests**: Run `uv run pytest tests/unit/` to verify your changes.
4. **Update the Index**: Synchronize [PROJECT_INDEX.md](PROJECT_INDEX.md) with any additions, removals, or modifications you made.

---

## 2. The Five Inviolable Invariants

Any code submitted by an AI agent must adhere strictly to these principles:

### Invariant 1: Source of Truth for Entity Text
Entity text is **always** sliced from the original or normalized input: `text[start:end]`. Never trust text returned by external models or detectors directly; always ground spans to source offsets.

### Invariant 2: Word-Bounded Alignment
Entity spans must always align to word boundaries. Sub-word fragments returned by statistical or machine learning models must be widened or discarded via `align_to_word_boundaries()`.

### Invariant 3: Offset-Based Right-to-Left Replacement
Pseudonymization must be performed strictly using character offsets from right to left (`end` to `start`). **`str.replace()` is strictly forbidden** for pseudonymization to prevent substring corruption and collision hazards.

### Invariant 4: Disjoint and Sorted Aggregation Spans
Entities emitted from the aggregation stage must be pairwise disjoint (non-overlapping), strictly sorted by start offset, and word-boundary aligned.

### Invariant 5: Core Framework Boundary & Import Hygiene
The core pipeline (`src/privacy_gateway/gateway.py`, `preprocessing/`, `aggregation/`, `policy/`, `pseudonymization/`, `reidentification/`) **must never import** heavy machine learning libraries (`torch`, `spacy`, `transformers`, `presidio_analyzer`) at module top-level. All heavy models are lazy-loaded inside `.warmup()` methods of their respective detector classes. Model-free unit tests must execute in `< 10` seconds.

---

## 3. Entity Policy & Exclusions Reference

The gateway enforces explicit policies for entity categories defined in [src/privacy_gateway/policy/actions.py](src/privacy_gateway/policy/actions.py):

### Pseudonymized Entities (Masked & Protected)
- `PERSON`, `EMPLOYEE`, `STAKEHOLDER` (`<PERSON_xxx>`)
- `EMAIL` (`<EMAIL_xxx>`)
- `PHONE` (`<PHONE_xxx>`)
- `CREDIT_CARD` (`<CARD_xxx>`)
- `SSN` (`<SSN_xxx>`)
- `DATE` (`<DATE_xxx>`): Calendar dates, birth dates, and expiration dates. (Bare clock timestamps like `00:04:12` or `10:30` are preserved as transcript structure).
- `INTERNAL_SYSTEM` (`<SYSTEM_xxx>`)
- `INTERNAL_SERVICE` (`<SERVICE_xxx>`)
- `CUSTOMER` (`<CUSTOMER_xxx>`)
- `PROJECT` (`<PROJECT_xxx>`)
- `CONTRACT` (`<CONTRACT_xxx>`)
- `CONFIDENTIAL_...` (`<CONFIDENTIAL_xxx>`): Credentials, passwords, connection strings.

### Excluded Entities (Action: ALLOW — Must Pass Through in Plain Text)
The following categories are **excluded** from detection and masking; they must remain in plain text:
- `ORGANIZATION`
- `LOCATION` / `ADDRESS` / `GEO`
- `PASSPORT` / `PASSPORT_NUMBER`
- `ACCOUNT_IDENTIFIER` / `CUSTOMER_ID` (including IBAN, bank account numbers)
- `IP_ADDRESS`
- `URL` / `INTERNAL_URL`
- `SESSION_TOKEN`
- `DEVICE_ID`

If you are asked to modify entity policies or add new entity types, update both [src/privacy_gateway/policy/actions.py](src/privacy_gateway/policy/actions.py) and the Policy Matrix in [PROJECT_INDEX.md](PROJECT_INDEX.md).

---

## 4. How to Update `PROJECT_INDEX.md`

When completing a task, check this list to update the relevant section in [PROJECT_INDEX.md](PROJECT_INDEX.md):

| If you modified... | Update this section in `PROJECT_INDEX.md` |
|---|---|
| Pipeline stages, lifecycle, or component flow | **Section 2: End-to-End Pipeline Workflow** & Mermaid diagram |
| Entity types, detector mappings, or policy actions | **Section 3: Entity Taxonomy & Current Policy Matrix** |
| Detector implementations or priority order | **Section 4: Detection Layers & Priorities** |
| Added, renamed, or moved files / directories | **Section 5: Complete Codebase Directory Map** |
| Added new test suites, commands, or CLI tools | **Section 6: Common Developer Commands** |

---

## 5. Standard Test Commands

Always verify changes using the standard project test suite:

```bash
# Run all fast, model-free unit tests (must pass in ~8s)
uv run pytest tests/unit/

# Run date and exclusion policy tests
uv run pytest tests/unit/test_date_and_exclusions.py

# Verify core import isolation
uv run pytest tests/unit/test_import_hygiene.py

# Run non-model regression tests
uv run pytest tests/regression/test_prototype_defects.py -m "not requires_models"
```
