// Download the NER model => npm run fetch:model [-- <org>/<name>]
// once, locally: runs then need no network


import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import "dotenv/config";
import { MODEL_ID, MODELS_DIR, NER_MODELS } from "../src/utils/ner_utils/ner_models";

const HUB = "https://huggingface.co";

const sha256Hex = (data: Buffer) => crypto.createHash("sha256").update(data).digest("hex");


// ======== Download one file to a temporary name, check it, then move it in place =========
async function download(url: string, target: string, sha256: string): Promise<void> {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    const data = Buffer.from(await res.arrayBuffer());
    const actual = sha256Hex(data);
    if (actual !== sha256) throw new Error(`${url}: SHA-256 is ${actual}, expected ${sha256}`);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(`${target}.part`, data);
    fs.renameSync(`${target}.part`, target);
}


async function main() {
    const id = process.argv[2] ?? MODEL_ID;
    const model = NER_MODELS[id];
    if (!model) throw new Error(`Unknown model "${id}". Known: ${Object.keys(NER_MODELS).join(", ")}.`);

    const dir = path.join(MODELS_DIR, id);
    for (const file of model.files) {
        const target = path.join(dir, file.to ?? file.from);
        if (fs.existsSync(target) && sha256Hex(fs.readFileSync(target)) === file.sha256) {
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
