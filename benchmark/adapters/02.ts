// 02-ts-lists-transformersjs-ner: redact() as `npm run dev` calls it, with the shipped lists.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { run } from "./_common";

async function main() {
    const root = path.resolve(__dirname, "../../02-ts-lists-transformersjs-ner");
    const { redact } = await import(pathToFileURL(path.join(root, "src/pii/redact.ts")).href);
    await run("02-ts-lists-transformersjs-ner", async (text) => (await redact(text)).text);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
