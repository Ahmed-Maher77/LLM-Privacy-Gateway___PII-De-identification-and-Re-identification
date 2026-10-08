// 06-ts-winknlp-lite: the configuration `npm run dev` uses (src/index.ts).
import path from "node:path";
import { pathToFileURL } from "node:url";
import { run } from "./_common";

const CONFIG = {
    EMAIL: true,
    URL: true,
    DATE: true,
    MONEY: false,
    PERSON: true,
    LOCATION: true,
    ORGANIZATION: true,
    MENTION: true,
    PHONE: true,
};

async function main() {
    const root = path.resolve(__dirname, "../../06-ts-winknlp-lite");
    const { detectPII, maskPII } = await import(pathToFileURL(path.join(root, "src/pii-masker.ts")).href);
    await run("06-ts-winknlp-lite", (text) => maskPII(detectPII(text, CONFIG), text));
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
