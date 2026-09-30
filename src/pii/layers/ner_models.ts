// NER models we can run: the pinned files `npm run fetch:model` downloads,
// and how each model's labels map to our types.

import path from "node:path";
import type { EntityType } from "../types";

export interface NerModel {
    revision: string; // Hugging Face commit, so every fetch gets the same files
    files: { from: string; to?: string; sha256: string }[];
    labels: Record<string, EntityType>; // model label without B-/I- -> our type; others are ignored
}

export const MODELS_DIR = path.resolve(__dirname, "../../../models");
export const DEFAULT_NER_MODEL = "gravitee-io/bert-small-pii-detection";

// Presidio's type names. ORGANIZATION is never taken: companies come only
// from the pre-defined list. Which of these to keep is decided in PLAN.md 2.4.
const PRESIDIO_STYLE_LABELS: Record<string, EntityType> = {
    PERSON: "PERSON",
    EMAIL_ADDRESS: "EMAIL_ADDRESS",
    PHONE_NUMBER: "PHONE_NUMBER",
    CREDIT_CARD: "CREDIT_CARD",
    IBAN_CODE: "IBAN_CODE",
    DATE_TIME: "DATE_TIME",
    US_SSN: "US_SSN",
    US_PASSPORT: "US_PASSPORT",
    US_DRIVER_LICENSE: "US_DRIVER_LICENSE",
};

export const NER_MODELS: Record<string, NerModel> = {
    // Apache-2.0, uncased BERT-small, 29 MB quantized
    "gravitee-io/bert-small-pii-detection": {
        revision: "f8c27a85c51c0168f07b9dcf00265bf0a4097939",
        files: [
            { from: "config.json", sha256: "6757df1ae2ec9ca16cef63009af337a66573d06c721d03c7820590f69eefa6c8" },
            { from: "tokenizer.json", sha256: "d241a60d5e8f04cc1b2b3e9ef7a4921b27bf526d9f6050ab90f9267a1f9e5c66" },
            { from: "tokenizer_config.json", sha256: "01a629a4923673b9a7a6d7da214952152c87c7ab3e002aae8e1e025486942163" },
            // At the repo root; Transformers.js looks for onnx/model_quantized.onnx
            { from: "model.quant.onnx", to: "onnx/model_quantized.onnx", sha256: "b227845ff4989c9f7383874b841895dfbdb9a4d7a20ceb39c3f187271894bf2a" },
        ],
        labels: PRESIDIO_STYLE_LABELS,
    },
};
