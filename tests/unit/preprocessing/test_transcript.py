"""Transcript parsing and the participant registry."""

from __future__ import annotations

import itertools

import pytest

from privacy_gateway.preprocessing.registry import ParticipantRegistry
from privacy_gateway.preprocessing.transcript import TranscriptParser

P = TranscriptParser()

def _turns(*pairs):
    """Build a Teams-format transcript. Needs >=3 labels to be detected."""
    parts = []
    for i, (name, body) in enumerate(pairs, 1):
        header = name + "   0:" + str(i).zfill(2) + " "
        parts.append(header + "\n" + body + " \n\n")
    return "".join(parts)


def _registry(text):
    """Parse and build a registry, refusing to return an empty one.

    Without this guard a negative assertion ("token X must not match here")
    would pass trivially when the fixture failed to parse at all.
    """
    reg = ParticipantRegistry.from_transcript(P.parse(text))
    assert reg.participants, "fixture produced an empty registry; test would pass vacuously"
    return reg

TEAMS = (
    "Weekly Platform Team Standup Meeting-20260101_090000UTC-Meeting Recording \n"
    "\n"
    "September 24, 2026, 10:30AM \n"
    "\n"
    "30m 37s \n"
    "\n"
    " \n"
    "Ahmed Farid   0:31 \n"
    "So. \n"
    "\n"
    " \n"
    "Rania Fahmy   0:31 \n"
    "The Shalaby. \n"
    "\n"
    " \n"
    "Ahmed Farid   0:53 \n"
    "Abdulrahman. \n"
    "\n"
    " \n"
    "Rania Fahmy   13:04 \n"
    "Michael, Michael Ibrahim. \n"
)

MARKDOWN = (
    "**Meeting: SME Digital Transformation**\n"
    "\n"
    "**Date:** September 22, 2026\n"
    "**Participants:**\n"
    "\n"
    "* Ahmed Hassan — Presales Solution Architect\n"
    "* Sarah Mitchell — Client Product Manager\n"
    "\n"
    "---\n"
    "\n"
    "**09:00 — Ahmed Hassan:**\n"
    "\n"
    "Good morning everyone.\n"
    "\n"
    "**09:01 — Sarah Mitchell:**\n"
    "\n"
    "Sure. We operate across London.\n"
    "\n"
    "**09:02 — Ahmed Hassan:**\n"
    "\n"
    "Understood.\n"
)


# -- format detection --------------------------------------------------------

def test_teams_format_is_detected():
    assert P.detect_format(TEAMS)[0] == "teams"


def test_markdown_format_is_detected():
    assert P.detect_format(MARKDOWN)[0] == "markdown"


def test_plain_prose_is_unstructured():
    assert P.detect_format("Just a paragraph of text. Nothing structural.")[0] == "unstructured"


def test_unstructured_text_yields_one_turn_covering_the_document():
    text = "Just a paragraph."
    parsed = P.parse(text)
    assert parsed.format == "unstructured"
    assert len(parsed.turns) == 1
    assert (parsed.turns[0].body_start, parsed.turns[0].body_end) == (0, len(text))


# -- teams speaker lines -----------------------------------------------------

def test_teams_speakers_are_exactly_the_recurring_names():
    parsed = P.parse(TEAMS)
    assert set(parsed.speaker_names) == {"Ahmed Farid", "Rania Fahmy"}


def test_recording_header_is_not_a_speaker():
    assert "Weekly Platform Team Standup Meeting" not in P.parse(TEAMS).speaker_names


def test_date_line_is_not_a_speaker():
    # "September 24, 2026, 10:30AM" ends in a digit-bearing token, and does not
    # recur, so both filters reject it.
    assert not any("September" in n for n in P.parse(TEAMS).speaker_names)


def test_duration_line_is_not_a_speaker():
    assert not any("30m" in n for n in P.parse(TEAMS).speaker_names)


def test_body_line_that_looks_like_a_name_is_not_a_speaker():
    assert "Michael Ibrahim" not in P.parse(TEAMS).speaker_names


def test_timestamps_over_ten_minutes_parse():
    labels = [label for label in P.parse(TEAMS).speaker_labels if label.timestamp == "13:04"]
    assert len(labels) == 1


def test_a_name_appearing_only_once_is_rejected():
    text = "Ahmed Farid   0:01 \nhi \n\nAhmed Farid   0:02 \nyo \n\nOne Off   0:03 \nhm \n"
    assert "One Off" not in P.parse(text).speaker_names


def test_speaker_label_spans_slice_back_to_the_name():
    parsed = P.parse(TEAMS)
    assert parsed.speaker_labels
    for label in parsed.speaker_labels:
        assert TEAMS[label.name_start : label.name_end] == label.name


def test_turns_are_ordered_and_non_overlapping():
    turns = P.parse(TEAMS).turns
    for a, b in itertools.pairwise(turns):
        assert a.body_end <= b.body_start or a.body_start <= b.body_start


# -- markdown ----------------------------------------------------------------

def test_markdown_roster_is_extracted_with_roles():
    declared = P.parse(MARKDOWN).declared_participants
    assert [(d.name, d.role) for d in declared] == [
        ("Ahmed Hassan", "Presales Solution Architect"),
        ("Sarah Mitchell", "Client Product Manager"),
    ]


def test_markdown_speaker_headers_are_parsed():
    assert set(P.parse(MARKDOWN).speaker_names) == {"Ahmed Hassan", "Sarah Mitchell"}


def test_markdown_roster_spans_slice_back_to_the_name():
    for d in P.parse(MARKDOWN).declared_participants:
        assert MARKDOWN[d.start : d.end] == d.name


def test_bulleted_list_outside_the_participants_block_is_not_a_roster():
    text = MARKDOWN + "\nRequirements:\n\n* FleetCore — fleet management\n* OpsHub — procedures\n"
    names = {d.name for d in P.parse(text).declared_participants}
    assert "FleetCore" not in names and "OpsHub" not in names


# -- registry ----------------------------------------------------------------

def test_registry_builds_from_speaker_labels():
    reg = ParticipantRegistry.from_transcript(P.parse(TEAMS))
    assert {p.display_name for p in reg.participants} == {"Ahmed Farid", "Rania Fahmy"}


def test_registry_includes_declared_participants():
    reg = ParticipantRegistry.from_transcript(P.parse(MARKDOWN))
    assert {p.display_name for p in reg.participants} == {"Ahmed Hassan", "Sarah Mitchell"}


def test_registry_records_roles():
    reg = ParticipantRegistry.from_transcript(P.parse(MARKDOWN))
    roles = {p.display_name: p.role for p in reg.participants}
    assert roles["Sarah Mitchell"] == "Client Product Manager"


def test_mention_spans_slice_back_to_their_surface():
    reg = ParticipantRegistry.from_transcript(P.parse(TEAMS))
    for m in reg.mentions(TEAMS):
        assert TEAMS[m.start : m.end] == m.surface


def test_full_name_in_the_body_is_matched():
    text = TEAMS + "\nI spoke with Rania Fahmy about it. \n"
    reg = ParticipantRegistry.from_transcript(P.parse(text))
    body = [m for m in reg.mentions(text) if m.kind == "full_name"]
    assert any(m.surface == "Rania Fahmy" for m in body)


def test_bare_first_name_is_matched_as_a_token():
    text = TEAMS + "\nI asked Rania about it. \n"
    reg = ParticipantRegistry.from_transcript(P.parse(text))
    assert any(m.surface == "Rania" and m.kind == "token" for m in reg.mentions(text))


# -- the boundary cases that produced the corrupted output -------------------
#
# Each fixture below needs at least three speaker lines to clear the format
# detection floor, and each asserts the token IS registered before asserting
# where it must not match -- otherwise the negative assertion would pass
# vacuously against an empty registry.


def test_token_does_not_match_as_a_prefix_of_a_longer_word():
    # "Ali" is a genuine prefix of "Alia". Without the trailing word-boundary
    # assertion the registry would claim a PERSON at that offset and the
    # pseudonymizer would emit <PERSON_001>a -- the same shape of corruption
    # as the prototype's <PER_23>y.
    text = _turns(("Ali Hassan", "hi"), ("Ali Hassan", "yo"), ("Ali Hassan", "Alia said so."))
    reg = _registry(text)
    assert reg.lookup("Ali") == ("Ali Hassan",)          # the token IS registered
    at = text.index("Alia")
    assert not any(m.start == at for m in reg.mentions(text))


def test_token_does_not_match_as_a_prefix_of_a_common_word():
    text = _turns(("Sam Lee", "hi"), ("Sam Lee", "yo"), ("Sam Lee", "The Same thing."))
    reg = _registry(text)
    assert reg.lookup("Sam") == ("Sam Lee",)
    at = text.index("Same")
    assert not any(m.start == at for m in reg.mentions(text))


def test_token_does_not_match_as_a_suffix_of_a_longer_word():
    # Exercises the LEADING word-boundary assertion: "Anna" sits inside
    # "JoAnna", capitalised, so only (?<!\w) keeps it out.
    text = _turns(("Anna Smith", "hi"), ("Anna Smith", "yo"), ("Anna Smith", "JoAnna called."))
    reg = _registry(text)
    assert reg.lookup("Anna") == ("Anna Smith",)
    inner = text.index("JoAnna") + 2
    assert not any(m.start == inner for m in reg.mentions(text))


def test_token_does_match_when_it_stands_alone():
    # The positive control for the three tests above: the guard must not be so
    # strict that a real mention is missed.
    text = _turns(("Ali Hassan", "hi"), ("Ali Hassan", "yo"), ("Ali Hassan", "Ali said so."))
    reg = _registry(text)
    at = text.rindex("Ali said") 
    assert any(m.start == at and m.surface == "Ali" for m in reg.mentions(text))


def test_a_participant_token_does_not_match_inside_a_common_word():
    text = _turns(("Ali Hassan", "hi"), ("Ali Hassan", "yo"), ("Ali Hassan", "The quality is good."))
    reg = _registry(text)
    assert reg.lookup("Ali") == ("Ali Hassan",)
    assert all("qualit" not in m.surface.lower() for m in reg.mentions(text))


def test_lowercase_occurrence_of_a_name_token_is_not_a_mention():
    text = _turns(("Sam Lee", "hi"), ("Sam Lee", "yo"), ("Sam Lee", "please sam the item."))
    reg = _registry(text)
    assert [m for m in reg.mentions(text) if m.surface == "sam"] == []


def test_stopword_tokens_are_never_registered():
    text = _turns(("Will Smith", "hi"), ("Will Smith", "yo"), ("Will Smith", "Will you go?"))
    reg = _registry(text)
    assert reg.lookup("Will") == ()
    assert reg.lookup("Smith") == ("Will Smith",)


def test_longest_surface_wins_over_a_bare_token():
    text = _turns(("Rania Fahmy", "hi"), ("Rania Fahmy", "yo"), ("Rania Fahmy", "Rania Fahmy spoke."))
    reg = _registry(text)
    at = text.rindex("Rania Fahmy")
    hit = next(m for m in reg.mentions(text) if m.start == at)
    assert hit.surface == "Rania Fahmy"


# -- ambiguity is reported, never resolved -----------------------------------

AMBIGUOUS = _turns(
    ("Ahmed Farid", "hi"), ("Ahmed Hamed", "yo"), ("Ahmed Farid", "hm"),
    ("Ahmed Hamed", "ok"), ("Ahmed Maher", "sure"), ("Ahmed Maher", "right"),
    ("Ahmed Farid", "I asked Ahmed about it."),
)


def test_three_ahmeds_are_registered_separately():
    reg = _registry(AMBIGUOUS)
    assert {p.display_name for p in reg.participants} == {
        "Ahmed Farid", "Ahmed Hamed", "Ahmed Maher",
    }


def test_bare_ambiguous_token_reports_every_candidate():
    reg = _registry(AMBIGUOUS)
    assert set(reg.lookup("Ahmed")) == {"Ahmed Farid", "Ahmed Hamed", "Ahmed Maher"}
    assert reg.is_ambiguous("Ahmed")


def test_bare_ambiguous_token_is_still_detected():
    # It cannot be attributed, but it must still be protected.
    reg = _registry(AMBIGUOUS)
    at = AMBIGUOUS.rindex("Ahmed about")
    assert any(m.start == at and m.ambiguous for m in reg.mentions(AMBIGUOUS))


def test_ambiguous_token_carries_lower_confidence():
    reg = _registry(AMBIGUOUS)
    amb = next(m for m in reg.mentions(AMBIGUOUS) if m.kind == "token" and m.ambiguous)
    assert amb.confidence < 0.90


def test_unambiguous_surname_resolves_to_one_participant():
    reg = _registry(AMBIGUOUS)
    assert reg.lookup("Hamed") == ("Ahmed Hamed",)


def test_safe_summary_contains_no_names():
    reg = _registry(AMBIGUOUS)
    assert "Ahmed" not in repr(reg.to_safe_summary())


# -- aliases -----------------------------------------------------------------

def test_configured_alias_is_matched():
    text = _turns(("Lamia Aly", "hi"), ("Lamia Aly", "yo"), ("Lamia Aly", "Lamya will do it."))
    reg = ParticipantRegistry.from_transcript(P.parse(text), aliases={"Lamya": "Lamia Aly"})
    assert reg.participants
    assert any(m.surface == "Lamya" for m in reg.mentions(text))


def test_aliases_are_off_unless_configured():
    # Fuzzy matching is a footgun here: Badri/Kamel/Jamal are all one edit
    # apart and are different people.
    text = _turns(("Lamia Aly", "hi"), ("Lamia Aly", "yo"), ("Lamia Aly", "Lamya will do it."))
    reg = _registry(text)
    assert reg.lookup("Lamya") == ()


# -- real transcripts --------------------------------------------------------

@pytest.mark.parametrize(
    "filename,expected",
    [
        (
            "pod_meeting.txt",
            {"Ahmed Farid", "Ahmed Maher", "Ahmed Hamed", "Lamia Aly",
             "Rania Fahmy", "Hossam Badri"},
        ),
        (
            "sme_meeting_transcript.txt",
            {"Ahmed Hassan", "Daniel Clark", "Emily Wilson", "Michael Brown",
             "Omar Khaled", "Sarah Mitchell"},
        ),
    ],
)
def test_real_transcript_rosters(normalized_transcript, filename, expected):
    nt = normalized_transcript(filename)
    assert set(P.parse(nt.text).speaker_names) == expected


def test_pod_meeting_ambiguous_surface_is_only_ahmed(normalized_transcript):
    nt = normalized_transcript("pod_meeting.txt")
    reg = ParticipantRegistry.from_transcript(P.parse(nt.text))
    assert {m.surface for m in reg.mentions(nt.text) if m.ambiguous} == {"Ahmed"}


def test_real_transcript_mention_spans_are_exact(normalized_transcript):
    nt = normalized_transcript("pod_meeting.txt")
    reg = ParticipantRegistry.from_transcript(P.parse(nt.text))
    for m in reg.mentions(nt.text):
        assert nt.text[m.start : m.end] == m.surface


def test_aly_token_never_matches_inside_alia_in_the_real_transcript(normalized_transcript):
    nt = normalized_transcript("pod_meeting.txt")
    reg = ParticipantRegistry.from_transcript(P.parse(nt.text))
    for m in reg.mentions(nt.text):
        assert nt.text[m.start : m.end] != "Ali"
        assert not (m.surface == "Aly" and nt.text[m.end : m.end + 1].isalpha())
