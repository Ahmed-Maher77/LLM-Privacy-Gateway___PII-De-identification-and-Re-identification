// Layer 3 — NER model (Transformers.js, local ONNX in models/)
  // the main source of PERSON. The model never gives offsets: the text is
  // split into pieces by regex, the model labels pieces, and a span's offsets
  // are its pieces' offsets. Design and choices: docs/transformers-js/DESIGN.md

import fs from "node:fs";
import path from "node:path";
import type { PreTrainedModel, PreTrainedTokenizer, Tensor } from "@huggingface/transformers" with { "resolution-mode": "import" };
import type { EntityType, PIISpan } from "../types";
import { isListedGivenName } from "./dictionary";
import { lineOf } from "./dictionary_helpers";
import { DEFAULT_NER_MODEL, MODELS_DIR, NER_MODELS, type NerModel } from "./ner_models";
import { isEnglishWord } from "./wink";

function numberFromEnv(name: string, fallback: number): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number.`);
  return value;
}

const MODEL_ID = process.env.NER_MODEL ?? DEFAULT_NER_MODEL;
const MIN_SCORE = numberFromEnv("NER_MIN_SCORE", 0.5); // provisional, tuned in PLAN.md 2.2
const WINDOW_TOKENS = Math.min(numberFromEnv("NER_WINDOW_TOKENS", 256), 510); // + [CLS] and [SEP] <= 512
const BATCH_SIZE = Math.max(1, numberFromEnv("NER_BATCH_SIZE", 8));
const OVERLAP_TOKENS = 64;

// Runs of letters/digits, or one punctuation mark or symbol: the split BERT's own pre-tokenizer makes
const PIECE_RE = /[^\s\p{P}\p{S}]+|[\p{P}\p{S}]/gu;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export class ModelLoadError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = "ModelLoadError";
  }
}

interface Loaded {
  tokenizer: PreTrainedTokenizer;
  model: PreTrainedModel;
  makeTensor: (data: BigInt64Array, dims: number[]) => Tensor;
  cls: number;
  sep: number;
  pad: number;
  id2label: Record<number, string>;
  info: NerModel;
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
  const missing = info.files.map((f) => f.to ?? f.from).filter((f) => !fs.existsSync(path.join(dir, f)));
  if (missing.length > 0) throw new ModelLoadError(`The NER model ${MODEL_ID} is not in ${dir}. Run \`npm run fetch:model\`.`);

  try {
    // An ES module: `import()` works from CommonJS where a static import does not typecheck
    const { env, AutoTokenizer, AutoModelForTokenClassification, Tensor } = await import("@huggingface/transformers");
    env.allowRemoteModels = false; // never download at run time
    env.allowLocalModels = true;
    env.localModelPath = MODELS_DIR;
    const [tokenizer, model] = await Promise.all([
      AutoTokenizer.from_pretrained(MODEL_ID),
      AutoModelForTokenClassification.from_pretrained(MODEL_ID, { dtype: "q8", device: "cpu" }),
    ]);
    const [cls, sep] = tokenizer.encode(""); // the model's own [CLS] [SEP] template
    const pad = tokenizer.pad_token_id ?? 0;
    const id2label = (model.config as unknown as { id2label: Record<number, string> }).id2label;
    const makeTensor = (data: BigInt64Array, dims: number[]) => new Tensor("int64", data, dims);
    return { tokenizer, model, makeTensor, cls, sep, pad, id2label, info };
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

// ======== Run one padded batch of windows, labelling each piece by its first sub-token =========
async function labelBatch(batch: Window[], m: Loaded): Promise<void> {
  const rows = batch.map((w) => [m.cls, ...w.pieces.flatMap((p) => p.ids), m.sep]);
  const width = Math.max(...rows.map((r) => r.length));
  const ids = new BigInt64Array(batch.length * width).fill(BigInt(m.pad));
  const mask = new BigInt64Array(batch.length * width);
  rows.forEach((r, b) => r.forEach((id, t) => ((ids[b * width + t] = BigInt(id)), (mask[b * width + t] = 1n))));

  const { logits } = await m.model({
    input_ids: m.makeTensor(ids, [batch.length, width]),
    attention_mask: m.makeTensor(mask, [batch.length, width]),
  });
  const [, tokens, classes] = logits.dims as number[];
  const data = logits.data as Float32Array;

  batch.forEach((w, b) => {
    const total = rows[b].length - 2;
    let t = 1; // after [CLS]
    for (const p of w.pieces) {
      const off = (b * tokens + t) * classes;
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
  });
}

// ======== Group labelled pieces into spans (B- starts, I- continues, O / type change / line break ends) =========
function group(text: string, ps: Piece[], m: Loaded): PIISpan[] {
  const spans: PIISpan[] = [];
  let open: { type: EntityType; first: Piece; last: Piece; scores: number[] } | undefined;
  const close = () => {
    if (!open) return;
    const score = open.scores.reduce((a, b) => a + b, 0) / open.scores.length;
    const { start } = open.first;
    const { end } = open.last;
    if (score >= MIN_SCORE) spans.push({ start, end, type: open.type, text: text.slice(start, end), score, source: "ner" });
    open = undefined;
  };

  for (const p of ps) {
    if (p.ids.length === 0) continue; // nothing for the model to see (e.g. a lone zero-width character)
    const [, prefix, name] = /^(?:([BI])-)?(.+)$/.exec(p.label ?? "O")!;
    const type = name === "O" ? undefined : m.info.labels[name];
    const lineBreak = open !== undefined && /[\r\n]/.test(text.slice(open.last.end, p.start));
    if (!type) {
      close();
    } else if (open && prefix !== "B" && open.type === type && !lineBreak) {
      open.last = p;
      open.scores.push(p.score!);
    } else {
      close();
      open = { type, first: p, last: p, scores: [p.score!] };
    }
  }
  close();
  return spans;
}

// ====== Check if a PERSON span looks like a real person name, not a random capitalized word or acronym ======
function looksLikePerson(span: PIISpan, text: string): boolean {
  const words = span.text.split(/\s+/);
  if (!/\p{L}/u.test(span.text)) return false;
  if (words.every((w) => isEnglishWord(w)) && !words.some((w) => isListedGivenName(w))) return false;
  return /\p{Lu}/u.test(span.text) || !/\p{Lu}/u.test(lineOf(text, span.start));
}

// ====== Trim a name to remove trailing whitespace and digits ======
function trimName(span: PIISpan, text: string): PIISpan | undefined {
  if (span.type !== "PERSON") return span;
  let value = span.text.split(/[\r\n]/)[0];
  value = value.replace(/\s*\S*\d[\s\S]*$/, "");
  value = value.replace(/[\s,.:;!?]+$/, "");
  if (!/\p{L}/u.test(value)) return undefined;
  return { ...span, end: span.start + value.length, text: text.slice(span.start, span.start + value.length) };
}

// =========== Detect PII in text with the local NER model =========
export async function detectNer(text: string): Promise<PIISpan[]> {
  const m = await (loading ??= loadModel());
  const ps = pieces(text, m);

  // A piece longer than a window (a base64 blob, say) is left as O; regex still sees it
  const seen = ps.filter((p) => p.ids.length > 0 && p.ids.length <= WINDOW_TOKENS);
  const ws = windows(seen);
  for (let i = 0; i < ws.length; i += BATCH_SIZE) await labelBatch(ws.slice(i, i + BATCH_SIZE), m);
  // No truncation: a piece the model never looked at would be a quiet leak
  if (seen.some((p) => p.label === undefined)) throw new Error("NER left a piece of the input unlabelled.");

  const spans = group(text, ps, m)
    .map((s) => trimName(s, text))
    .filter((s): s is PIISpan => s !== undefined)
    // A phone label can land on an IPv4 address ("192.168.14.22")
    .filter((s) => !(s.type === "PHONE_NUMBER" && IPV4_RE.test(s.text)))
    .filter((s) => s.type !== "PERSON" || looksLikePerson(s, text));

  // Offsets come from our pieces; if one ever drifted, every mask would be wrong
  for (const s of spans) {
    if (s.start < 0 || s.end > text.length || s.text !== text.slice(s.start, s.end)) {
      throw new Error("NER span offsets don't match the input; refusing to guess offsets.");
    }
  }
  return spans;
}
