// 03-ts-winknlp-regex-rules-poc: the configuration `npm run demo` uses (defaults plus dates,
// numbered, coreference-aware placeholders).
import path from "node:path";
import { pathToFileURL } from "node:url";
import { run } from "./_common";

async function main() {
    const root = path.resolve(__dirname, "../../03-ts-winknlp-regex-rules-poc");
    const { detectPII } = await import(pathToFileURL(path.join(root, "src/pii/detector.ts")).href);
    const { maskPIIWithMapping } = await import(pathToFileURL(path.join(root, "src/pii/masker.ts")).href);
    await run("03-ts-winknlp-regex-rules-poc", (text) =>
        maskPIIWithMapping(text, detectPII(text, { date: true }), { numbered: true }).maskedText,
    );
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
