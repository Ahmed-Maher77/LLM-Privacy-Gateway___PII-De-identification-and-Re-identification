// The NER model's vocabulary as a common-word list: a common word is one whole token in it
// ("hope", "will", but also "sarah"; not "kofi")

import fs from "node:fs";
import path from "node:path";
import { MODEL_DIR, ModelLoadError } from "./ner_models";

let vocab: Set<string> | undefined;

function load(): Set<string> {
    const file = path.join(MODEL_DIR, "tokenizer.json");
    try {
        const words = Object.keys(JSON.parse(fs.readFileSync(file, "utf-8")).model.vocab);
        return new Set(words.filter((w) => !w.startsWith("##")));   // filter out subword tokens
    } catch (err) {
        throw new ModelLoadError(`${file} could not be read. Run \`npm run fetch:model\`.`, err);
    }
}

export function isCommonWord(word: string): boolean {
    return (vocab ??= load()).has(word.toLowerCase());
}
