"""Regenerate resources/common_words.txt.

Deliberately a curated list rather than a scraped frequency table. The spaCy
model shipped here has no populated probability column, and a list assembled
from an arbitrary corpus would be both unreproducible and wrong in the places
that matter. What this list has to cover is narrow and knowable: ordinary
English words that a generic NER model mislabels as a proper noun in meeting
minutes and standup transcripts.

Several entries are here because the prototype's committed output shows them
being corrupted or mis-detected: "nice", "content", "control", "contract",
"conversation", "composer", "next".
"""

from __future__ import annotations

import pathlib

BUSINESS = ["operations", "operation", "finance", "financial", "accounting", "marketing", "sales", "support", "service", "services", "system", "systems", "platform", "platforms", "product", "products", "project", "projects", "team", "teams", "company", "companies", "business", "customer", "customers", "client", "clients", "employee", "employees", "user", "users", "data", "database", "report", "reports", "meeting", "meetings", "document", "documents", "process", "processes", "integration", "integrations", "application", "applications", "software", "hardware", "network", "security", "access", "control", "controls", "quality", "testing", "development", "deployment", "production", "staging", "environment", "environments", "release", "releases", "version", "versions", "feature", "features", "requirement", "requirements", "story", "stories", "sprint", "sprints", "backlog", "roadmap", "timeline", "budget", "cost", "costs", "price", "pricing", "revenue", "profit", "contract", "contracts", "agreement", "invoice", "payment", "account", "accounts", "record", "records", "history", "log", "logs", "audit", "compliance", "policy", "policies", "procedure", "procedures", "standard", "standards", "framework", "architecture", "design", "designs", "review", "reviews", "approval", "decision", "decisions", "action", "actions", "item", "items", "issue", "issues", "risk", "risks", "problem", "problems", "solution", "solutions", "option", "options", "plan", "plans", "phase", "phases", "stage", "stages", "step", "steps", "task", "tasks", "goal", "goals", "objective", "objectives", "scope", "schedule", "delivery", "deliverable", "deliverables", "summary", "overview", "introduction", "conclusion", "question", "questions", "answer", "answers", "note", "notes", "comment", "comments", "update", "updates", "change", "changes", "request", "requests", "response", "responses", "migration", "onboarding", "training", "documentation", "dashboard", "dashboards", "workflow", "workflows", "pipeline", "pipelines", "repository", "branch", "branches", "commit", "ticket", "tickets", "board", "sprint", "demo", "estimate", "estimates", "capacity", "resource", "resources", "vendor", "vendors", "partner", "partners", "stakeholder", "stakeholders", "manager", "director", "engineer", "developer", "designer", "analyst", "architect", "consultant", "admin", "administrator", "owner", "lead"]

GENERAL = ["nice", "next", "last", "first", "second", "third", "fourth", "final", "early", "late", "good", "great", "fine", "okay", "sure", "right", "correct", "wrong", "true", "false", "content", "contents", "conversation", "conversations", "composer", "control", "today", "tomorrow", "yesterday", "morning", "afternoon", "evening", "night", "week", "weeks", "month", "months", "year", "years", "time", "times", "date", "dates", "day", "days", "hour", "hours", "minute", "minutes", "name", "names", "number", "numbers", "list", "lists", "group", "groups", "type", "types", "kind", "kinds", "level", "levels", "reference", "references", "source", "sources", "target", "targets", "result", "results", "value", "values", "example", "examples", "case", "cases", "point", "points", "part", "parts", "side", "end", "start", "begin", "beginning", "middle", "top", "bottom", "left", "right", "front", "back", "thing", "things", "way", "ways", "place", "places", "area", "areas", "line", "lines", "page", "pages", "word", "words", "text", "section", "sections", "title", "header", "footer", "subject", "topic", "topics", "detail", "details", "fact", "facts", "idea", "ideas", "reason", "reasons", "purpose", "result", "effect", "impact", "benefit", "benefits", "feature", "help", "question", "answer", "people", "person", "everyone", "someone", "anyone", "nobody", "everybody", "something", "anything", "nothing", "everything", "here", "there", "where", "when", "what", "which", "who", "whom", "whose", "how", "why", "because", "although", "however", "therefore", "meanwhile", "otherwise", "instead", "please", "thanks", "thank", "sorry", "hello", "goodbye", "new", "no"]

TECH = ["server", "servers", "client", "cloud", "local", "remote", "host", "hosting", "endpoint", "endpoints", "request", "response", "payload", "header", "token", "session", "cookie", "cache", "queue", "worker", "job", "jobs", "batch", "stream", "streaming", "model", "models", "agent", "agents", "prompt", "prompts", "context", "window", "memory", "storage", "backup", "restore", "index", "search", "query", "filter", "sort", "export", "import", "upload", "download", "sync", "async", "error", "errors", "warning", "warnings", "debug", "trace", "metric", "metrics", "monitor", "monitoring", "alert", "alerts", "latency", "throughput", "performance", "scale", "scaling", "capacity", "load", "test", "tests", "suite", "coverage", "mock", "stub", "fixture"]

#: Interview and meeting role labels ("Interviewer:", "Witness:",
#: "Observer:"), several of which are also ordinary adjectives that can appear
#: unrelated to any label elsewhere in the same document. "External" is here
#: because a header line "Observer: Amara Nwosu (External Advisor, ...)" got
#: "External" detected as a standalone ORGANIZATION, which then case-
#: insensitively collided with the ordinary phrase "an external observer"
#: later in the transcript body and was reported as a leak of the mapped
#: value -- the same class of bug as "operations", just a different word.
ROLES = ["interviewer", "interviewee", "interview", "interviews", "observer",
         "witness", "facilitator", "secretary", "chair", "moderator", "note",
         "taker", "reporter", "advisor", "consultant", "expert", "specialist",
         "official", "representative", "delegate", "counsel", "attorney",
         "internal", "external", "environmental", "primary", "secondary",
         "senior", "junior", "principal", "chief", "assistant", "associate",
         "deputy", "acting", "interim", "former", "current", "prior",
         "present", "absent", "confidential", "privileged", "public",
         "private", "unofficial", "hearing", "hearings", "arbitration",
         "arbitrator", "claimant", "claimants", "respondent", "respondents",
         "petitioner", "petitioners", "plaintiff", "defendant"]


def build() -> list[str]:
    words = {w.lower() for w in (*BUSINESS, *GENERAL, *TECH, *ROLES) if len(w) >= 2}
    return sorted(words)


HEADER = """\
# Ordinary English words.
#
# A statistical detector that labels one of these as a PERSON, ORGANIZATION or
# LOCATION is almost certainly wrong. Protecting such a "name" both destroys
# the sentence and floods the mapping with a word that then appears to leak
# everywhere else in the document -- which is how a single false positive on
# "operations" turns into fifteen pre-send leak findings.
#
# The filter applies ONLY to single-token spans from statistical detectors
# (presidio, ner, qwen). A curated domain term, a regex match and a transcript
# speaker label are never filtered, so a company genuinely called "Apple" is
# still protected through the lexicon, and a participant called "Mark" is still
# protected through the registry.
#
# Curated, not scraped. Regenerate with scripts/build_common_words.py
"""


def main() -> None:
    words = build()
    path = pathlib.Path(__file__).resolve().parents[1] / "resources" / "common_words.txt"
    path.write_text(HEADER + "\n".join(words) + "\n", encoding="utf-8")
    print(f"wrote {len(words)} words to {path}")


if __name__ == "__main__":
    main()
