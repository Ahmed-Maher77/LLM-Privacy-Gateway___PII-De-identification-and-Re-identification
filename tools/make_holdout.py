"""Generate a held-out corpus whose labels are exact by construction.

The fixture corpus was written by hand and then fixed against, round after
round. Whatever it measures, it cannot measure generalisation: every value in
it has been seen by whoever tuned the thresholds. This builds a second corpus
from name and identifier pools that appear nowhere in the fixtures, and records
each span's offset at the moment it is inserted rather than searching for it
afterwards. Nothing here is derived, so every document ships ``gold_complete``
from the start.

The templates are not a sample of realistic documents. Each one targets a
specific piece of logic that span metrics alone cannot exercise -- two people
who share a surname, a first name that is also an ordinary word, an acronym
that collides with a technical one -- because a wrong merge and a missed merge
both produce perfectly correct spans and differ only in which placeholder they
land on.

**This corpus is scored, never tuned against.** Reading a failure is fine.
Adding a value from these pools to an allowlist, a pattern, ``COMMON_WORDS`` or
a threshold is not: it converts the only independent measurement into another
fixture. Reproduce the failure in ``tests/fixtures/`` with fresh values, fix it
there, then re-run this. ``tests/test_holdout.py`` enforces the rule by failing
if any pool value appears anywhere in ``pii/``.
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools.scoring import GoldSpan  # noqa: E402

SEED = 20260927
HOLDOUT_DIR = PROJECT_ROOT / "tests" / "holdout"
FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures"

# Every literal the generator can emit as PII. Kept in one structure so the
# disjointness check and the "never tuned against" check have a single source.
POOLS: dict[str, tuple[str, ...]] = {
    "given_names": (
        "Ayodele", "Thandiwe", "Bardhyl", "Solveig", "Ingibjorg", "Nandor",
        "Gulzar", "Oyelaran", "Marisol", "Eirlys", "Kwabena", "Anneliese",
    ),
    "surnames": (
        "Ramachandran", "Vuorinen", "Okonkwo-Baptiste", "Sigurdardottir",
        "Aldercott", "Kone", "Szabolcsi", "Nguyen-Baptiste", "Delacroix-Mwangi",
    ),
    "common_word_names": ("Will", "Grace", "Mark", "Summer", "Rose"),
    "orgs": (
        "Norvane Interchange Bureau", "Kestrelon Consulting Inc.",
        "Vireloq Group", "Vireloq Capital", "Quillon Analytics Ltd",
    ),
    "cities": ("Trondheim", "Kumasi", "Ballarat", "Pecs", "Antofagasta"),
    "domains": ("norvane-ib.example", "quillon-analytics.example"),
    "record_ids": ("NVN-704821", "QA-2031-884", "REF-99120-XZ"),
    "phones": ("+44 20 8081 0733", "+1 (509) 555-0164"),
    "ibans": ("GB94BARC20201530093459",),
    "cards": ("4716349812340027",),
}

# Non-PII lookalikes. These must survive redaction untouched; each becomes a
# gold negative, so an over-redaction of one is a countable false positive.
CONTROLS: tuple[tuple[str, str], ...] = (
    ("v3.11.2", "semantic version"),
    ("a4f9c21", "commit sha"),
    ("10.0.0.0/8", "CIDR block"),
    ("2026-03-14", "ISO date"),
    ("AES-256-GCM", "cipher suite"),
    ("CVE-2026-1111", "vulnerability id"),
    ("HTTP/1.1", "protocol version"),
    ("P95", "latency percentile"),
    ("SLA", "technical acronym"),
    ("TLS", "technical acronym"),
)


def fixture_tokens() -> set[str]:
    """Every word and labelled value appearing in the tuned corpus."""
    tokens: set[str] = set()
    for path in sorted(FIXTURE_DIR.glob("*.txt")):
        tokens.update(re.findall(r"[\w'-]+", path.read_text(encoding="utf-8")))
    for path in sorted(FIXTURE_DIR.glob("*.expected.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        for key in ("must_redact", "must_keep"):
            for item in data.get(key, []):
                value = item["value"] if isinstance(item, dict) else item
                tokens.update(re.findall(r"[\w'-]+", str(value)))
    return tokens


# Words that carry no identity on their own. "Consulting" appearing in both
# corpora says nothing about whether a name was seen during tuning, and
# "example" is the reserved TLD from RFC 2606, which any synthetic corpus will
# use. Everything else must be genuinely fresh.
GENERIC_TOKENS = frozenset(
    """
    example consulting group capital partners holdings limited analytics
    bureau interchange services solutions systems global
    """.split()
)


def assert_disjoint(pools: dict[str, tuple[str, ...]], forbidden: set[str]) -> None:
    """Fail at generation time if a pool value was already seen in tuning.

    Checked per token, not per whole value: "Kestrelon Consulting Inc." would
    pass a naive string check while sharing "Harbor" with a fixture, and a name
    the tuner has already seen is not held out in any useful sense.
    """
    collisions: list[str] = []
    for name, values in pools.items():
        for value in values:
            for token in re.findall(r"[\w'-]+", value):
                if len(token) < 4 or token.casefold() in GENERIC_TOKENS:
                    continue  # "Inc", "Ltd", "Consulting": not identifying alone
                if token in forbidden:
                    collisions.append(f"{name}: {value!r} shares token {token!r}")
    if collisions:
        raise SystemExit(
            "Holdout pools overlap the tuned corpus:\n  " + "\n  ".join(sorted(set(collisions)))
        )


@dataclass
class Builder:
    """Assembles a document while recording every span as it is written."""

    parts: list[str] = field(default_factory=list)
    spans: list[GoldSpan] = field(default_factory=list)
    negatives: list[dict] = field(default_factory=list)
    _length: int = 0

    def text(self, chunk: str) -> Builder:
        self.parts.append(chunk)
        self._length += len(chunk)
        return self

    def pii(self, value: str, label: str, entity: str = "") -> Builder:
        start = self._length
        self.text(value)
        self.spans.append(
            GoldSpan(start=start, end=start + len(value), label=label,
                     text=value, entity=entity, origin="generated")
        )
        return self

    def control(self, value: str, reason: str) -> Builder:
        start = self._length
        self.text(value)
        self.negatives.append({"start": start, "end": start + len(value),
                               "text": value, "reason": reason})
        return self

    def line(self, chunk: str = "") -> Builder:
        return self.text(chunk + "\n")

    def finish(self) -> tuple[str, list[GoldSpan], list[dict]]:
        return "".join(self.parts), self.spans, self.negatives


# --- Templates ---------------------------------------------------------------

def t_shared_surname(rng: random.Random) -> tuple[Builder, dict]:
    """Two people, one surname. A bare mention belongs to neither.

    The unique-owner rule in entities.link_short_forms only attaches a short
    form when exactly one full name owns it. With two owners it must attach to
    neither, and collapsing them onto one placeholder would silently merge two
    people into one.
    """
    b = Builder()
    b.line("PROJECT REVIEW -- ACCESS REQUEST").line()
    b.text("Requester: ").pii("Ayodele Ramachandran", "PERSON", "e1").line(" (Platform)")
    b.text("Approver:  ").pii("Solveig Ramachandran", "PERSON", "e2").line(" (Security)")
    b.line()
    b.text("Both reviewers share a surname; the ticket lists ")
    b.pii("Ayodele Ramachandran", "PERSON", "e1").line(" as owner.")
    b.text("Escalation goes to ").pii("Solveig Ramachandran", "PERSON", "e2").line(" only.")
    b.text("The change was tagged ").control("v3.11.2", "semantic version").line(".")
    return b, {"expect_distinct_entities": [["e1", "e2"]]}


def t_common_word_first_name(rng: random.Random) -> tuple[Builder, dict]:
    """People named Will, Grace and Mark, in prose that also uses the words.

    roster.COMMON_WORDS blocks propagating a bare "will", but a sentence-initial
    "Will you approve this?" is capitalised exactly like the name, and the
    capitalisation rule is what decides. Both readings appear here.
    """
    b = Builder()
    b.line("STANDUP NOTES").line()
    b.text("Attendees: ").pii("Will Vuorinen", "PERSON", "e1").text(", ")
    b.pii("Grace Aldercott", "PERSON", "e2").line()
    b.line()
    b.control("Will", "sentence-initial modal verb").line(" you approve the rollout today?")
    b.pii("Will Vuorinen", "PERSON", "e1").line(": I can, once the soak test passes.")
    b.control("Mark", "sentence-initial imperative verb").line(" the ticket as resolved afterwards.")
    b.text("We will need ").pii("Grace Aldercott", "PERSON", "e2").line(" to sign off on the audit.")
    b.line("Please mark the runbook and note we will revisit next week.")
    return b, {"expect_distinct_entities": [["e1", "e2"]]}


def t_first_initial_forms(rng: random.Random) -> tuple[Builder, dict]:
    """One person written four ways; all must reach one placeholder."""
    b = Builder()
    b.line("INTERVIEW LOG").line()
    b.text("Candidate: ").pii("Ayodele Kone", "PERSON", "e1").line()
    b.text("Short form: ").pii("Ayodele K.", "PERSON", "e1").line()
    b.text("Initial form: ").pii("A. Kone", "PERSON", "e1").line()
    b.text("Indexed as: ").pii("Kone, Ayodele", "PERSON", "e1").line()
    b.text("Reference id ").control("REF-99120-XZ", "internal reference, not a person").line()
    return b, {"expect_same_entity": [["e1"]]}


def t_acronym_collision(rng: random.Random) -> tuple[Builder, dict]:
    """An organisation acronym beside genuinely technical ones.

    Every named body here is a control: ORG is outside the balanced profile,
    so the question is whether the acronym NIB drags anything else into a
    redaction, not whether the organisation itself is removed.
    """
    b = Builder()
    b.line("ARCHITECTURE REVIEW").line()
    b.text("Sponsor: ").control("Norvane Interchange Bureau", "ORG, outside the balanced profile").line(" (NIB)")
    b.line()
    b.text("NIB requires that every endpoint negotiate ").control("TLS", "technical acronym")
    b.text(" 1.3 with ").control("AES-256-GCM", "cipher suite").line(".")
    b.text("The ").control("SLA", "technical acronym").text(" target is ")
    b.control("P95", "latency percentile").line(" under 200ms.")
    b.text("Tracking ").control("CVE-2026-1111", "vulnerability id").line(" separately.")
    return b, {}


def t_org_prefix_traps(rng: random.Random) -> tuple[Builder, dict]:
    """A shared prefix that must merge, beside one that must not.

    The organisations are controls (ORG is outside the balanced profile); the
    two people carrying those names as surnames are the actual targets, so the
    merge logic is exercised through a type that is genuinely redacted.
    """
    b = Builder()
    b.line("VENDOR SHORTLIST").line()
    b.text("1. ").control("Kestrelon Consulting Inc.", "ORG, outside the balanced profile").line()
    b.text("   Referred to throughout as ").control("Kestrelon", "ORG, outside the balanced profile").line(".")
    b.text("2. ").control("Vireloq Group", "ORG, outside the balanced profile").line()
    b.text("3. ").control("Vireloq Capital", "ORG, outside the balanced profile").line()
    b.text("Account manager: ").pii("Anneliese Kestrelon", "PERSON", "e1").line()
    b.text("Her colleague ").pii("Marisol Vireloq", "PERSON", "e2").line(" covers the other two.")
    b.line("The two Vireloq entities are unrelated companies.")
    return b, {"expect_distinct_entities": [["e1", "e2"]]}


def t_honorific_pairs(rng: random.Random) -> tuple[Builder, dict]:
    """Two people, one surname, distinguished only by honorific."""
    b = Builder()
    b.line("CASE NOTE").line()
    b.text("Present: ").pii("Ms. Aldercott", "PERSON", "e1").text(" and ")
    b.pii("Mr. Aldercott", "PERSON", "e2").line(" (no relation).")
    b.text("").pii("Ms. Aldercott", "PERSON", "e1").line(" gave evidence first.")
    b.text("").pii("Mr. Aldercott", "PERSON", "e2").line(" was called after the recess.")
    return b, {"expect_distinct_entities": [["e1", "e2"]]}


def t_unseen_names(rng: random.Random) -> tuple[Builder, dict]:
    """Names outside the Anglo range, with particles and diacritics.

    The city is a control, not a target: LOCATION sits outside the balanced
    profile by design, on the reasoning that a city is quasi-identifying at
    most. Labelling it must-redact would measure this generator's assumption
    rather than the redactor's behaviour.
    """
    b = Builder()
    b.line("CROSS-BORDER CALL").line()
    b.text("Chair: ").pii("Ingibjorg Sigurdardottir", "PERSON", "e1").line(" (Reykjavik)")
    b.text("Counsel: ").pii("Bardhyl Szabolcsi", "PERSON", "e2").line()
    b.text("Analyst: ").pii("Thandiwe Okonkwo-Baptiste", "PERSON", "e3").line()
    b.text("Observer: ").pii("Nandor Delacroix-Mwangi", "PERSON", "e4").line()
    b.text("Dialing in from ").control("Trondheim", "LOCATION, outside the balanced profile").line(".")
    b.text("Contact ").pii("ayodele.kone@norvane-ib.example", "EMAIL", "e6").line()
    return b, {"expect_distinct_entities": [["e1", "e2", "e3", "e4"]]}


def t_noisy_asr(rng: random.Random) -> tuple[Builder, dict]:
    """Lowercase, unpunctuated, one name transcribed two ways."""
    b = Builder()
    b.line("raw transcript no punctuation")
    b.text("so ").pii("ayodele", "PERSON", "e1").line(" said the migration would land friday")
    b.text("then ").pii("ayo delay", "PERSON", "e1").line(" corrected himself it was thursday")
    b.line("the number he read out was five zero nine five five five zero one six four")
    return b, {}


def t_structured_records(rng: random.Random) -> tuple[Builder, dict]:
    """CSV, key-value and a fixed-width table with a wide column gap."""
    b = Builder()
    b.line("name,role,reference")
    b.pii("Kwabena Kone", "PERSON", "e1").text(",Engineer,").pii("NVN-704821", "CUSTOM_ID", "e2").line()
    b.line()
    b.text("Owner:      ").pii("Marisol Vuorinen", "PERSON", "e3").line()
    b.text("Phone:      ").pii("+44 20 8081 0733", "PHONE", "e4").line()
    b.line()
    b.line("NAME                   ROLE")
    b.pii("Eirlys Aldercott", "PERSON", "e5").line("        Principal Architect")
    return b, {}


def t_code_and_config(rng: random.Random) -> tuple[Builder, dict]:
    """A credential inside a URI, beside non-PII lookalikes."""
    b = Builder()
    b.line("# deploy.yaml").line()
    b.text("database_url: ")
    b.pii("postgresql://svc_norvane:Hunter2Seven@db.internal:5432/ledger",
          "CONNECTION_STRING", "e1").line()
    b.text("allowed_cidr: ").control("10.0.0.0/8", "CIDR block").line()
    b.text("build_sha: ").control("a4f9c21", "commit sha").line()
    b.text("released: ").control("2026-03-14", "ISO date").line()
    b.text("protocol: ").control("HTTP/1.1", "protocol version").line()
    b.text("contact: ").pii("ops@quillon-analytics.example", "EMAIL", "e2").line()
    return b, {}


def t_zero_pii_control(rng: random.Random) -> tuple[Builder, dict]:
    """Nothing to redact. The output must be byte-identical."""
    b = Builder()
    b.line("PERFORMANCE NOTES").line()
    b.line("The p95 latency regressed after the cache eviction policy changed.")
    b.text("We pinned the runtime at ").control("v3.11.2", "semantic version").line(".")
    b.text("Traffic is restricted to ").control("10.0.0.0/8", "CIDR block").line(".")
    b.text("Transport is ").control("AES-256-GCM", "cipher suite").text(" over ")
    b.control("TLS", "technical acronym").line(" 1.3.")
    b.line("No customer records were involved in this investigation.")
    return b, {"byte_identical": True}


def t_placeholder_injection_control(rng: random.Random) -> tuple[Builder, dict]:
    """Input that already contains placeholder-shaped literals."""
    b = Builder()
    b.line("TICKET BODY").line()
    b.line("The customer pasted a template they found: {{PERSON_1}} and ${TOKEN_2}.")
    b.text("Reported by ").pii("Anneliese Vuorinen", "PERSON", "e1").line(".")
    return b, {"expect_escaped_literals": ["{{PERSON_1}}"]}


TEMPLATES = {
    "shared_surname": t_shared_surname,
    "common_word_first_name": t_common_word_first_name,
    "first_initial_forms": t_first_initial_forms,
    "acronym_collision": t_acronym_collision,
    "org_prefix_traps": t_org_prefix_traps,
    "honorific_pairs": t_honorific_pairs,
    "unseen_names": t_unseen_names,
    "noisy_asr": t_noisy_asr,
    "structured_records": t_structured_records,
    "code_and_config": t_code_and_config,
    "zero_pii_control": t_zero_pii_control,
    "placeholder_injection_control": t_placeholder_injection_control,
}


def build(out_dir: Path, seed: int = SEED) -> list[str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for index, (name, template) in enumerate(sorted(TEMPLATES.items()), start=1):
        rng = random.Random(seed + index)
        builder, assertions = template(rng)
        source, spans, negatives = builder.finish()

        for span in spans:
            actual = source[span.start : span.end]
            assert actual == span.text, f"{name}: offset drift, {actual!r} != {span.text!r}"

        stem = f"holdout_{index:02d}_{name}"
        (out_dir / f"{stem}.txt").write_text(source, encoding="utf-8")

        by_entity: dict[str, list[str]] = {}
        for span in spans:
            if span.entity:
                by_entity.setdefault(span.entity, [])
                if span.text not in by_entity[span.entity]:
                    by_entity[span.entity].append(span.text)

        expected = {
            "schema": 2,
            "generated_by": "tools/make_holdout.py",
            "seed": seed,
            # Exact by construction, so this is true from the first write.
            "gold_complete": True,
            "must_redact": sorted({s.text for s in spans}),
            "must_keep": [n["text"] for n in negatives],
            "same_entity": [v for v in by_entity.values() if len(v) > 1],
            "gold_spans": [s.as_dict() for s in spans],
            "gold_negatives": negatives,
            "assertions": assertions,
        }
        (out_dir / f"{stem}.expected.json").write_text(
            json.dumps(expected, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        written.append(stem)
        print(f"  {stem:48} {len(spans):3} spans, {len(negatives):2} controls")
    return written


def main() -> int:
    description = (__doc__ or "").splitlines()[0] if __doc__ else None
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--out", default=str(HOLDOUT_DIR))
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--check", action="store_true", help="verify pools are disjoint only")
    args = parser.parse_args()

    assert_disjoint(POOLS, fixture_tokens())
    if args.check:
        print("Holdout pools are disjoint from the tuned corpus.")
        return 0

    written = build(Path(args.out), args.seed)
    print(f"\nWrote {len(written)} held-out documents to {args.out}")
    print("This corpus is scored, never tuned against. See the module docstring.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
