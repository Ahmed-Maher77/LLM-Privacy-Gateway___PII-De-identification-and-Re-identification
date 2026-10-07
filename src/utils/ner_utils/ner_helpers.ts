import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import {
    MODEL_DIR,
    MODEL_ID,
    MODELS_DIR,
    ModelLoadError,
    NER_MODELS,
} from "./ner_models";
import { Loaded, Piece, PIISpan, Window } from "../../pii/types";
import { numberFromEnv } from "../envGetter";
import {
    isAllCaps,
    lineOf,
    NEVER_NAMES,
    TITLES,
} from "../predefinedLists_utils/text_helpers";

// ======== NER Model Configuration =========
const MIN_SCORE = numberFromEnv("NER_MIN_SCORE", 0.5);
const WINDOW_TOKENS = Math.min(numberFromEnv("NER_WINDOW_TOKENS", 384), 510); // BERT context window is 512, but we add [CLS] and [SEP] tokens
const OVERLAP_TOKENS = numberFromEnv("NER_OVERLAP_TOKENS", 32);
const THREADS = Math.max(1, Math.floor(os.availableParallelism() / 2));

// ========= Regexes =========
const PIECE_RE = /[^\s\p{P}\p{S}]+|[\p{P}\p{S}]/gu; // split text into pieces/words depends on punctuation
const LABEL_RE = /^(?:([BI])-)?(.+)$/; // "B-PERSON" -> B, PERSON
const LETTERS_RE = /^[\p{L}\p{M}]+$/u; // a piece made only of letters (no punctuation, digits or symbols)
const JOINER_RE = /^[.'’-]$/; // joiner characters (apostrophes, hyphens, etc.) => "Al-Rashid"

// ======== Load the tokenizer and model (once per process) =========
async function loadModel(): Promise<Loaded> {
    // check the model is present and complete, and get its metadata
    const info = NER_MODELS[MODEL_ID];
    if (!info)
        throw new ModelLoadError(
            `Unknown NER_MODEL "${MODEL_ID}". Known: ${Object.keys(NER_MODELS).join(", ")}.`,
        );
    if (
        info.files.some(
            (f) => !fs.existsSync(path.join(MODEL_DIR, f.to ?? f.from)),
        )
    ) {
        throw new ModelLoadError(
            `The NER model ${MODEL_ID} is not in ${MODEL_DIR}. Run \`npm run fetch:model\`.`,
        );
    }

    try {
        // load the Transformers.js model and tokenizer (local ONNX, no downloads at run time)
        const { env, AutoTokenizer, AutoModelForTokenClassification, Tensor } =
            await import("@huggingface/transformers");
        env.allowRemoteModels = false;
        env.localModelPath = MODELS_DIR;
        const [tokenizer, model] = await Promise.all([
            AutoTokenizer.from_pretrained(MODEL_ID),
            AutoModelForTokenClassification.from_pretrained(MODEL_ID, {
                dtype: "q8",
                device: "cpu",
                session_options: { intraOpNumThreads: THREADS },
            }),
        ]);

        const [cls, sep] = tokenizer.encode(""); // the model's own [CLS] [SEP] template
        const id2label = (
            model.config as unknown as { id2label: Record<number, string> }
        ).id2label;
        const makeTensor = (data: BigInt64Array) =>
            new Tensor("int64", data, [1, data.length]);

        return {
            tokenizer,
            model,
            makeTensor,
            cls,
            sep,
            id2label,
            person: info.person,
        };
    } catch (err) {
        throw new ModelLoadError(
            `The NER model ${MODEL_ID} in ${MODEL_DIR} could not be loaded. Run \`npm run fetch:model\`.`,
            err,
        );
    }
}

// ======== Split text into pieces/words and tokenize each one on its own =========
function pieces(text: string, m: Loaded): Piece[] {
    const cache = new Map<string, number[]>();
    const out: Piece[] = [];

    // avoid calling the tokenizer on the same piece twice
    for (const match of text.matchAll(PIECE_RE)) {
        let ids = cache.get(match[0]);
        if (!ids)
            cache.set(
                match[0],
                (ids = m.tokenizer.encode(match[0], {
                    add_special_tokens: false,
                })),
            );
        out.push({
            start: match.index,
            end: match.index + match[0].length,
            ids,
        });
    }
    return out;
}

// ======== Pack pieces into overlapping windows =========
function windows(ps: Piece[]): Window[] {
    const out: Window[] = [];
    for (let i = 0; i < ps.length; ) {
        let j = i;
        let tokens = 0;
        while (j < ps.length && tokens + ps[j].ids.length <= WINDOW_TOKENS)
            tokens += ps[j++].ids.length;

        // cutStart / cutEnd: the window starts or ends inside the text, not at its own start or end
        out.push({
            pieces: ps.slice(i, j),
            cutStart: i > 0,
            cutEnd: j < ps.length,
        });
        if (j >= ps.length) break;
        let k = j;
        let back = 0;
        while (k > i + 1 && back + ps[k - 1].ids.length <= OVERLAP_TOKENS)
            back += ps[--k].ids.length;
        i = k;
    }
    return out;
}

// ======== Run the model on one window, labelling and scoring each piece =========
async function labelWindow(w: Window, m: Loaded): Promise<void> {
    const row = [m.cls, ...w.pieces.flatMap((p) => p.ids), m.sep];
    const { logits } = await m.model({
        input_ids: m.makeTensor(BigInt64Array.from(row, BigInt)),
        attention_mask: m.makeTensor(new BigInt64Array(row.length).fill(1n)),
    });
    const classes = (logits.dims as number[])[2];
    const data = logits.data as Float32Array;

    // Get the label and confidence score for each piece
    const total = row.length - 2;
    let t = 1; // after [CLS]
    for (const p of w.pieces) {
        const off = t * classes;

        // Finding the highest-scoring class
        let best = 0;
        for (let c = 1; c < classes; c++)
            if (data[off + c] > data[off + best]) best = c;
        let sum = 0;
        for (let c = 0; c < classes; c++)
            sum += Math.exp(data[off + c] - data[off + best]);
        const before = w.cutStart ? t - 1 : Infinity;
        const after = w.cutEnd ? total - (t - 1 + p.ids.length) : Infinity;
        const edge = Math.min(before, after);

        // A piece seen in two windows keeps the label from the one where it has more context
        if (p.edge === undefined || edge > p.edge)
            Object.assign(p, { label: m.id2label[best], score: 1 / sum, edge });
        t += p.ids.length;
    }
}

// ======== Group labelled pieces into name spans, across joiners ("Al-Rashid", "O'Brien") =========
function group(text: string, ps: Piece[], m: Loaded): PIISpan[] {
    const spans: PIISpan[] = [];
    let open: { start: number; end: number; scores: number[] } | undefined;
    const close = () => {
        if (!open) return;
        const score =
            open.scores.reduce((a, b) => a + b, 0) / open.scores.length;
        spans.push({
            start: open.start,
            end: open.end,
            type: "PERSON",
            text: text.slice(open.start, open.end),
            score,
            source: "ner",
        });
        open = undefined;
    };

    for (const p of ps) {
        // check the validity of the piece (non-empty + has letters)
        if (p.ids.length === 0) continue;
        const [, prefix, name] = LABEL_RE.exec(p.label ?? "O")!;
        const value = text.slice(p.start, p.end);
        const letters = LETTERS_RE.test(value);
        if (
            open &&
            name === m.person &&
            prefix !== "B" &&
            !/[\r\n]/.test(text.slice(open.end, p.start))
        ) {
            if (JOINER_RE.test(value)) continue; // kept only if a letter piece follows
            if (letters) {
                open.end = p.end;
                open.scores.push(p.score!);
                continue;
            }
        }
        close();
        if (name === m.person && letters)
            open = { start: p.start, end: p.end, scores: [p.score!] };
    }
    close();
    return spans;
}

// ======== Join spans into a single name (ex: "Mohsen Saad") =========
function join(text: string, spans: PIISpan[]): PIISpan[] {
    const out: PIISpan[] = [];
    for (const s of spans) {
        const last = out[out.length - 1];
        if (last && /^(?:[ \t]+|\.)$/.test(text.slice(last.end, s.start))) {
            out[out.length - 1] = {
                ...last,
                end: s.end,
                text: text.slice(last.start, s.end),
                score: Math.max(last.score!, s.score!),
            };
        } else {
            out.push(s);
        }
    }
    return out;
}

// ====== Trim titles and never-names at both edges ("Mr", "Dr.", "hi", "bye") ======
function trimEdges(span: PIISpan, text: string): PIISpan | undefined {
    const words = [...span.text.matchAll(/\S+/g)];
    const title = (w: string) => TITLES.has(w.replace(/\.$/, "").toLowerCase());
    const never = (w: string) => title(w) || NEVER_NAMES.has(w.toLowerCase());
    let first = 0;
    let last = words.length - 1;

    // trim the edges as long as it hits never word
    for (let i = 1; i < last; i++) if (title(words[i][0])) first = i;
    while (first <= last && never(words[first][0])) first++;
    while (last >= first && never(words[last][0])) last--;
    if (first > last) return undefined;

    // calculate the new start and end positions
    const start = span.start + words[first].index;
    const end = span.start + words[last].index + words[last][0].length;
    return { ...span, start, end, text: text.slice(start, end) };
}

// ====== Check if a PERSON span looks like a real person name, not an acronym ======
function looksLikePerson(span: PIISpan, text: string): boolean {
    const words = span.text.split(/\s+/);
    const line = lineOf(text, span.start);
    const rest = line.replace(span.text, "");
    if (
        words.every(isAllCaps) &&
        !(/\p{Lu}/u.test(rest) && !/\p{Ll}/u.test(rest))
    )
        return false;
    return /\p{Lu}/u.test(span.text) || !/\p{Lu}/u.test(line);
}

export {
    loadModel,
    pieces,
    windows,
    labelWindow,
    group,
    join,
    trimEdges,
    looksLikePerson,
    MIN_SCORE,
    WINDOW_TOKENS,
};
