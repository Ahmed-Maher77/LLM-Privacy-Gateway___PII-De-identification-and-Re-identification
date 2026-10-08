// 04-ts-multilayer-lists-regex-ner-winknlp: redact() as `npm run dev` calls it, with the shipped list.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { run } from "./_common";

async function main() {
    const root = path.resolve(__dirname, "../../04-ts-multilayer-lists-regex-ner-winknlp");
    const { redact } = await import(pathToFileURL(path.join(root, "src/pii/redact.ts")).href);
    await run("04-ts-multilayer-lists-regex-ner-winknlp", async (text) => (await redact(text)).text);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
