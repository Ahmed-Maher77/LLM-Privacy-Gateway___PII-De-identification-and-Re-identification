// Model download => npm run fetch:model [-- <org>/<name>]
//   Downloads the pinned files of the NER model (NER_MODEL, or the default)
//   into models/<org>/<name>/, checks each SHA-256, and lays them out as
//   Transformers.js expects. This is the only step that needs the network:
//   the pipeline itself never downloads anything.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { DEFAULT_NER_MODEL, MODELS_DIR, NER_MODELS } from "../src/pii/layers/ner_models";

const HUB = "https://huggingface.co";

function sha256Of(file: string): string {
    return crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");
}

// ======== Download one file to a temporary name, check it, then move it in place =========
async function download(url: string, target: string, sha256: string): Promise<void> {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    const data = Buffer.from(await res.arrayBuffer());
    const actual = crypto.createHash("sha256").update(data).digest("hex");
    if (actual !== sha256) throw new Error(`${url}: SHA-256 is ${actual}, expected ${sha256}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(`${target}.part`, data);
    fs.renameSync(`${target}.part`, target);
}

async function main() {
    const id = process.argv[2] ?? process.env.NER_MODEL ?? DEFAULT_NER_MODEL;
    const model = NER_MODELS[id];
    if (!model) throw new Error(`Unknown model "${id}". Known: ${Object.keys(NER_MODELS).join(", ")}.`);

    const dir = path.join(MODELS_DIR, id);
    for (const file of model.files) {
        const target = path.join(dir, file.to ?? file.from);
        if (fs.existsSync(target) && sha256Of(target) === file.sha256) {
            console.log(`ok       ${file.to ?? file.from}`);
            continue;
        }
        await download(`${HUB}/${id}/resolve/${model.revision}/${file.from}`, target, file.sha256);
        console.log(`fetched  ${file.to ?? file.from}`);
    }
    console.log(`\n${id} @ ${model.revision.slice(0, 7)} is in ${path.relative(process.cwd(), dir)}`);
}

main().catch((err) => {
    console.error(err instanceof Error ? err.message : err);
    process.exit(1);
});
