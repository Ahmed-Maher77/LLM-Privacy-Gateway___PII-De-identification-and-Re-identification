// Layer 3 — NER model (Transformers.js, local ONNX in models/)
  // the main source of PERSON. The model never gives offsets: the text is
  // split into pieces by regex, the model labels pieces, and a span's offsets
  // are its pieces' offsets. Design and choices: docs/transformers-js/DESIGN.md

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { PreTrainedModel, PreTrainedTokenizer, Tensor } from "@huggingface/transformers" with { "resolution-mode": "import" };
import type { PIISpan } from "../types";
import { isListedGivenName } from "./dictionary";
import { isAllCaps, lineOf, NEVER_NAMES, TITLES } from "./dictionary_helpers";
import { DEFAULT_NER_MODEL, MODELS_DIR, NER_MODELS } from "./ner_models";
import { isEnglishWord } from "./wink";

function numberFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number.`);
  return value;
}

const MODEL_ID = process.env.NER_MODEL ?? DEFAULT_NER_MODEL;
const MIN_SCORE = numberFromEnv("NER_MIN_SCORE", 0.5);
const WINDOW_TOKENS = Math.min(numberFromEnv("NER_WINDOW_TOKENS", 384), 510); // + [CLS] and [SEP] <= 512
const OVERLAP_TOKENS = 32;
// onnxruntime's own default ran like 2 threads here; one per physical core was fastest
const THREADS = numberFromEnv("NER_THREADS", Math.max(1, Math.floor(os.availableParallelism() / 2)));

// Runs of letters/digits, or one punctuation mark or symbol: close to the split BERT's own pre-tokenizer makes
const PIECE_RE = /[^\s\p{P}\p{S}]+|[\p{P}\p{S}]/gu;
const LABEL_RE = /^(?:([BI])-)?(.+)$/; // "B-PERSON" -> B, PERSON
const LETTERS_RE = /^[\p{L}\p{M}]+$/u;
const JOINER_RE = /^[.'’-]$/;

export class ModelLoadError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "ModelLoadError";
  }
}

interface Loaded {
  tokenizer: PreTrainedTokenizer;
  model: PreTrainedModel;
  makeTensor: (data: BigInt64Array) => Tensor;
  cls: number;
  sep: number;
  id2label: Record<number, string>;
  person: string;
}

interface Piece {
  start: number;
  end: number;
  ids: number[];
  label?: string;
  score?: number;
  edge?: number; // sub-tokens to the nearer cut edge of the window it was labelled in
}

// A window's edge is "cut" where it splits the text; the text's own start and end are not
interface Window {
  pieces: Piece[];
  cutStart: boolean;
  cutEnd: boolean;
}

// ======== Load the tokenizer and model once per process =========
let loading: Promise<Loaded> | undefined;

async function loadModel(): Promise<Loaded> {
  const info = NER_MODELS[MODEL_ID];
  if (!info) throw new ModelLoadError(`Unknown NER_MODEL "${MODEL_ID}". Known: ${Object.keys(NER_MODELS).join(", ")}.`);
  const dir = path.join(MODELS_DIR, MODEL_ID);
  if (info.files.some((f) => !fs.existsSync(path.join(dir, f.to ?? f.from)))) {
    throw new ModelLoadError(`The NER model ${MODEL_ID} is not in ${dir}. Run \`npm run fetch:model\`.`);
  }

  try {
    // An ES module: `import()` works from CommonJS where a static import does not typecheck
    const { env, AutoTokenizer, AutoModelForTokenClassification, Tensor } = await import("@huggingface/transformers");
    env.allowRemoteModels = false; // never download at run time
    env.localModelPath = MODELS_DIR;
    const [tokenizer, model] = await Promise.all([
      AutoTokenizer.from_pretrained(MODEL_ID),
      AutoModelForTokenClassification.from_pretrained(MODEL_ID, { dtype: "q8", device: "cpu", session_options: { intraOpNumThreads: THREADS } }),
    ]);
    const [cls, sep] = tokenizer.encode(""); // the model's own [CLS] [SEP] template
    const id2label = (model.config as unknown as { id2label: Record<number, string> }).id2label;
    const makeTensor = (data: BigInt64Array) => new Tensor("int64", data, [1, data.length]);
    return { tokenizer, model, makeTensor, cls, sep, id2label, person: info.person };
  } catch (err) {
    throw new ModelLoadError(`The NER model ${MODEL_ID} in ${dir} could not be loaded. Run \`npm run fetch:model\`.`, err);
  }
}

// ======== Split text into pieces and tokenize each one on its own =========
function pieces(text: string, m: Loaded): Piece[] {
  const cache = new Map<string, number[]>();
  const out: Piece[] = [];
  for (const match of text.matchAll(PIECE_RE)) {
    let ids = cache.get(match[0]);
    if (!ids) cache.set(match[0], (ids = m.tokenizer.encode(match[0], { add_special_tokens: false })));
    out.push({ start: match.index, end: match.index + match[0].length, ids });
  }
  return out;
}

// ======== Pack pieces into windows of at most WINDOW_TOKENS sub-tokens, overlapping by ~OVERLAP_TOKENS =========
function windows(ps: Piece[]): Window[] {
  const out: Window[] = [];
  for (let i = 0; i < ps.length; ) {
    let j = i;
    let tokens = 0;
    while (j < ps.length && tokens + ps[j].ids.length <= WINDOW_TOKENS) tokens += ps[j++].ids.length;
    out.push({ pieces: ps.slice(i, j), cutStart: i > 0, cutEnd: j < ps.length });
    if (j >= ps.length) break;
    let k = j;
    let back = 0;
    while (k > i + 1 && back + ps[k - 1].ids.length <= OVERLAP_TOKENS) back += ps[--k].ids.length;
    i = k;
  }
  return out;
}

// ======== Run the model on one window, labelling each piece by its first sub-token =========
// One window per call: batching padded windows was slower on the CPU.
async function labelWindow(w: Window, m: Loaded): Promise<void> {
  const row = [m.cls, ...w.pieces.flatMap((p) => p.ids), m.sep];
  const { logits } = await m.model({
    input_ids: m.makeTensor(BigInt64Array.from(row, BigInt)),
    attention_mask: m.makeTensor(new BigInt64Array(row.length).fill(1n)),
  });
  const classes = (logits.dims as number[])[2];
  const data = logits.data as Float32Array;

  const total = row.length - 2;
  let t = 1; // after [CLS]
  for (const p of w.pieces) {
    const off = t * classes;
    let best = 0;
    for (let c = 1; c < classes; c++) if (data[off + c] > data[off + best]) best = c;
    let sum = 0;
    for (let c = 0; c < classes; c++) sum += Math.exp(data[off + c] - data[off + best]);
    const before = w.cutStart ? t - 1 : Infinity;
    const after = w.cutEnd ? total - (t - 1 + p.ids.length) : Infinity;
    const edge = Math.min(before, after);
    // A piece seen in two windows keeps the label from the one where it has more context
    if (p.edge === undefined || edge > p.edge) Object.assign(p, { label: m.id2label[best], score: 1 / sum, edge });
    t += p.ids.length;
  }
}

// ======== Group labelled pieces into name spans =========
// B- starts a span, I- continues it. A span is made of letter pieces and may
// continue across the joiners . ' ’ - ("Al-Rashid", "O'Brien"); anything else
// (O, other punctuation, a digit, a line break) ends it.
function group(text: string, ps: Piece[], m: Loaded): PIISpan[] {
  const spans: PIISpan[] = [];
  let open: { start: number; end: number; scores: number[] } | undefined;
  const close = () => {
    if (!open) return;
    const score = open.scores.reduce((a, b) => a + b, 0) / open.scores.length;
    spans.push({ start: open.start, end: open.end, type: "PERSON", text: text.slice(open.start, open.end), score, source: "ner" });
    open = undefined;
  };

  for (const p of ps) {
    if (p.ids.length === 0) continue; // nothing for the model to see (e.g. a lone zero-width character)
    const [, prefix, name] = LABEL_RE.exec(p.label ?? "O")!;
    const value = text.slice(p.start, p.end);
    const letters = LETTERS_RE.test(value);
    if (open && name === m.person && prefix !== "B" && !/[\r\n]/.test(text.slice(open.end, p.start))) {
      if (JOINER_RE.test(value)) continue; // kept only if a letter piece follows
      if (letters) {
        open.end = p.end;
        open.scores.push(p.score!);
        continue;
      }
    }
    close();
    if (name === m.person && letters) open = { start: p.start, end: p.end, scores: [p.score!] };
  }
  close();
  return spans;
}

// ======== Join name spans on one line separated only by spaces/tabs or a single "." ("kofi mensah", "J.L. Picard") =========
// The model often tags each word of a name B-; joined, the name gets one placeholder,
// and is kept or dropped as a whole: it takes its stronger part's score.
function join(text: string, spans: PIISpan[]): PIISpan[] {
  const out: PIISpan[] = [];
  for (const s of spans) {
    const last = out[out.length - 1];
    if (last && /^(?:[ \t]+|\.)$/.test(text.slice(last.end, s.start))) {
      out[out.length - 1] = { ...last, end: s.end, text: text.slice(last.start, s.end), score: Math.max(last.score!, s.score!) };
    } else {
      out.push(s);
    }
  }
  return out;
}

// ====== Trim titles and never-names at both edges ("Mr", "Dr.", "hi", "bye"), and leading English words that aren't given names ("Agent David") ======
// A span with nothing left ("Mr", "Salam", "Audio") is dropped; "Grace" and "Will" stay because they are listed given names.
// Ordinary English words are not trimmed at the end: a surname could be one.
function trimEdges(span: PIISpan, text: string): PIISpan | undefined {
  const words = [...span.text.matchAll(/\S+/g)];
  const title = (w: string) => TITLES.has(w.replace(/\.$/, "").toLowerCase());
  const never = (w: string) => title(w) || NEVER_NAMES.has(w.toLowerCase());
  let first = 0;
  let last = words.length - 1;
  // Words before an inner title aren't part of the name: "thank you mister el hamed" -> "el hamed"
  for (let i = 1; i < last; i++) if (title(words[i][0])) first = i;
  while (first <= last && (never(words[first][0]) || (isEnglishWord(words[first][0]) && !isListedGivenName(words[first][0])))) first++;
  while (last >= first && never(words[last][0])) last--;
  if (first > last) return undefined;
  const start = span.start + words[first].index;
  const end = span.start + words[last].index + words[last][0].length;
  return { ...span, start, end, text: text.slice(start, end) };
}

// ====== Check if a PERSON span looks like a real person name, not an acronym ======
function looksLikePerson(span: PIISpan, text: string): boolean {
  const words = span.text.split(/\s+/);
  const line = lineOf(text, span.start);
  // "FHIR", "AA": acronyms, unless the rest of the line is in capitals too
  const rest = line.replace(span.text, "");
  if (words.every(isAllCaps) && !(/\p{Lu}/u.test(rest) && !/\p{Ll}/u.test(rest))) return false;
  return /\p{Lu}/u.test(span.text) || !/\p{Lu}/u.test(line); // a lowercase name only on an all-lowercase line
}

// =========== Detect names in text with the local NER model =========
export async function detectNer(text: string): Promise<PIISpan[]> {
  const m = await (loading ??= loadModel());
  const ps = pieces(text, m);

  // A piece longer than a window (a base64 blob, say) is left as O; regex still sees it
  const seen = ps.filter((p) => p.ids.length > 0 && p.ids.length <= WINDOW_TOKENS);
  for (const w of windows(seen)) await labelWindow(w, m);
  // No truncation: a piece the model never looked at would be a quiet leak
  if (seen.some((p) => p.label === undefined)) throw new Error("NER left a piece of the input unlabelled.");

  const spans = join(text, group(text, ps, m))
    .filter((s) => s.score! >= MIN_SCORE)
    .map((s) => trimEdges(s, text))
    .filter((s): s is PIISpan => s !== undefined && looksLikePerson(s, text));

  // Offsets come from our pieces; if one ever drifted, every mask would be wrong
  for (const s of spans) {
    if (s.start < 0 || s.end > text.length || s.text !== text.slice(s.start, s.end)) {
      throw new Error("NER span offsets don't match the input; refusing to guess offsets.");
    }
  }
  return spans;
}
