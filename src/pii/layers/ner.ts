// Layer 2 — NER model (Transformers.js, local ONNX): the NLP source

import type { Loaded, PIISpan } from "../types";
import {
    labelWindow,
    loadModel,
    looksLikePerson,
    MIN_SCORE,
    pieces,
    trimEdges,
    WINDOW_TOKENS,
    windows,
    group,
    join,
} from "../../utils/ner_utils/ner_helpers";
export { ModelLoadError } from "../../utils/ner_utils/ner_models";

// ======== Load the model (once per process) =========
let loading: Promise<Loaded> | undefined;

// =========== Detect names in text with the local NER model =========
export async function detectNer(text: string): Promise<PIISpan[]> {
    const m = await (loading ??= loadModel());
    const ps = pieces(text, m);

    // check if a piece is valid (has tokens and is within the window size)
    const seen = ps.filter(
        (p) => p.ids.length > 0 && p.ids.length <= WINDOW_TOKENS,
    );

    // convert pieces into windows + label each window
    for (const w of windows(seen)) await labelWindow(w, m);

    if (seen.some((p) => p.label === undefined))
        throw new Error("NER left a piece of the input unlabelled.");

    // group labelled pieces into spans + join adjacent spans + trim edges + filter by score and validity
    const spans = join(text, group(text, ps, m))
        .filter((s) => s.score! >= MIN_SCORE)
        .map((s) => trimEdges(s, text))
        .filter(
            (s): s is PIISpan => s !== undefined && looksLikePerson(s, text),
        );

    // no span should be invalid (out of bounds or text mismatch)
    for (const s of spans) {
        if (
            s.start < 0 ||
            s.end > text.length ||
            s.text !== text.slice(s.start, s.end)
        ) {
            throw new Error(
                "NER span offsets don't match the input; refusing to guess offsets.",
            );
        }
    }
    return spans;
}
