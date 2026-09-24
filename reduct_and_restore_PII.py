from transformers import pipeline
from email_regex import EMAIL_PATTERN


# Initialize the NER pipeline with a pre-trained model
ner = pipeline(
    "ner",
    model="dslim/bert-base-NER",
    aggregation_strategy="simple"
)


class PIIMiddleware:
    # Anonymize text by replacing PII with placeholders
    def anonymize(self, text: str):
        entities = ner(text)

        mapping = {}
        counters = {}
        placeholders_by_original = {}

        def add_mapping(entity_type: str, original: str) -> None:
            if original in placeholders_by_original:
                return

            entity_type_count = counters[entity_type] = counters.get(entity_type, 0) + 1
            placeholder = f"<{entity_type}_{entity_type_count}>"
            placeholders_by_original[original] = placeholder
            mapping[placeholder] = original

        for match in EMAIL_PATTERN.finditer(text):
            add_mapping("EMAIL", match.group())

        for entity in entities:
            add_mapping(entity["entity_group"], entity["word"])

        anonymized = text
        for placeholder, original in sorted(
            mapping.items(),
            key=lambda item: len(item[1]),
            reverse=True,
        ):
            anonymized = anonymized.replace(original, placeholder)

        return anonymized, mapping


    # Restore text by replacing placeholders with original PII
    def restore(self, text: str, mapping: dict):
        # Replace longer placeholders first
        for placeholder, original in sorted(
            mapping.items(),
            key=lambda x: len(x[0]),
            reverse=True
        ):
            text = text.replace(
                placeholder,
                original
            )

        return text