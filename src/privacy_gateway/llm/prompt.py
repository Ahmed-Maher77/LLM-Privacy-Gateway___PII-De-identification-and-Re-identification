"""Prompt construction.

The system prompt states the placeholder contract explicitly. This is the
cheapest of the three drift mitigations and in practice removes most of it --
the model that produced ``**PER 2**`` in this repository's committed output
was never told the tokens were opaque identifiers, because the prototype sent
the bare transcript with no instruction at all.

Nothing here ever receives the mapping. The wrapper sees only the sanitized
text and the set of placeholders that appear in it.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_INSTRUCTION = (
    "Summarise the following meeting transcript. Cover the key decisions, "
    "action items, owners and open questions."
)

PLACEHOLDER_CONTRACT = """\
The text contains opaque identifiers of the form <TYPE_NNN>, for example \
<PERSON_001> or <ORG_002>. They stand in for real names and identifiers that \
you have not been given.

Rules for these identifiers:
1. Reproduce them character for character, including the angle brackets and \
the underscore. Do not add markdown emphasis inside or immediately around them.
2. Treat two identical identifiers as the same entity, and two different \
identifiers as different entities.
3. Never invent a new identifier, and never write a range such as \
"PERSON 3-8". If you need to refer to someone who has no identifier, describe \
them instead.
4. Do not guess what any identifier stands for.\
"""


@dataclass(frozen=True, slots=True)
class Prompt:
    system: str
    user: str


class PromptWrapper:
    """Builds the system and user messages for a sanitized document."""

    def __init__(
        self,
        instruction: str = DEFAULT_INSTRUCTION,
        contract: str = PLACEHOLDER_CONTRACT,
        include_contract: bool = True,
    ) -> None:
        self.instruction = instruction
        self.contract = contract
        self.include_contract = include_contract

    def wrap(self, sanitized_text: str, instruction: str | None = None) -> Prompt:
        system = self.contract if self.include_contract else ""
        user = f"{instruction or self.instruction}\n\n{sanitized_text}"
        return Prompt(system=system, user=user)

    def correction(self, malformed: tuple[str, ...]) -> str:
        """A single corrective turn quoting the specific malformed tokens."""
        shown = ", ".join(repr(t) for t in malformed[:10])
        return (
            "Your previous response altered some identifiers. "
            f"These tokens are malformed: {shown}. "
            "Rewrite your answer using the identifiers exactly as they appeared "
            "in the input, in the form <TYPE_NNN>, with no markdown emphasis "
            "inside or around them, and invent no new identifiers."
        )
