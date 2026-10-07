// Builds the name and place lists => npm run build:lists
//   Downloads open registries and writes data/lists/*.txt (one value per
//   line). Run it again to refresh the lists; the files are committed so the
//   pipeline itself never needs the network.
//
//   given-names.txt    Wikidata given names (labels + English aliases), CC0
//   surnames.txt       Wikidata family names, CC0 (census.gov blocks automated downloads)
//   places.txt         GeoNames cities (pop. >= 15,000), regions and countries, CC BY 4.0
//
// Wikidata is queried through QLever (qlever.dev), a fast public mirror; the
// official endpoint times out on these sizes.

import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";

const OUT_DIR = path.join(__dirname, "..", "data", "lists");
const USER_AGENT = "pii-list-builder/1.0";
const QLEVER = "https://qlever.dev/api/wikidata";
const PREFIXES =
  "PREFIX wd: <http://www.wikidata.org/entity/> PREFIX wdt: <http://www.wikidata.org/prop/direct/> " +
  "PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#> PREFIX skos: <http://www.w3.org/2004/02/skos/core#> " +
  "PREFIX wikibase: <http://wikiba.se/ontology#> ";

const GIVEN_NAME_CLASSES = "wd:Q202444 wd:Q12308941 wd:Q11879590 wd:Q3409032"; // given / male / female / unisex

async function download(url: string, init: RequestInit = {}): Promise<Buffer> {
  const res = await fetch(url, { ...init, headers: { "User-Agent": USER_AGENT, ...init.headers } });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return Buffer.from(await res.arrayBuffer());
}

/** Values of the single ?l column of a SPARQL query. */
async function sparql(query: string): Promise<string[]> {
  const url = `${QLEVER}?query=${encodeURIComponent(PREFIXES + query)}`;
  const tsv = (await download(url, { headers: { Accept: "text/tab-separated-values" } })).toString("utf-8");
  return tsv
    .split("\n")
    .slice(1)
    .map((line) => line.replace(/^"(.*)"(?:@[\w-]+)?$/, "$1").replace(/\\"/g, '"'))
    .filter(Boolean);
}

/** Minimal ZIP reader (the sources ship .zip files): returns one entry's content. */
function unzip(zip: Buffer, entryName: string): Buffer {
  const eocd = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  let p = zip.readUInt32LE(eocd + 16);
  for (let i = 0, n = zip.readUInt16LE(eocd + 10); i < n; i++) {
    const method = zip.readUInt16LE(p + 10);
    const size = zip.readUInt32LE(p + 20);
    const nameLen = zip.readUInt16LE(p + 28);
    const extraLen = zip.readUInt16LE(p + 30);
    const commentLen = zip.readUInt16LE(p + 32);
    const local = zip.readUInt32LE(p + 42);
    const name = zip.toString("utf-8", p + 46, p + 46 + nameLen);
    if (name === entryName) {
      const start = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
      const data = zip.subarray(start, start + size);
      return method === 0 ? data : zlib.inflateRawSync(data);
    }
    p += 46 + nameLen + extraLen + commentLen;
  }
  throw new Error(`${entryName} not found in zip`);
}

// A person name: 1–3 Latin-script words, each capitalised ("Abdel Rahman", "El-Hamed").
const NAME_RE = /^\p{Lu}[\p{Ll}'’]*(?:-\p{Lu}?[\p{Ll}'’]+)*(?: \p{Lu}[\p{Ll}'’]*(?:-\p{Lu}?[\p{Ll}'’]+)*){0,2}$/u;
const LATIN_RE = /^[\p{Script=Latin}\s'’.&,()0-9-]+$/u;

function cleanNames(values: string[]): string[] {
  return values.filter((v) => v.length >= 2 && v.length <= 30 && LATIN_RE.test(v) && NAME_RE.test(v) && !/\bname\b/i.test(v));
}


function write(file: string, header: string[], values: Iterable<string>): void {
  const sorted = [...new Set(values)].sort((a, b) => a.localeCompare(b, "en"));
  const lines = [...header.map((h) => `# ${h}`), `# Built ${new Date().toISOString().slice(0, 10)} by scripts/build-lists.ts. ${sorted.length} entries.`, ...sorted];
  fs.writeFileSync(path.join(OUT_DIR, file), lines.join("\n") + "\n", "utf-8");
  console.log(`${file.padEnd(18)} ${sorted.length}`);
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  // ---- Given names
  let given: string[] = [];
  for (const lang of ["en", "mul"]) {
    given = given.concat(await sparql(`SELECT ?l WHERE { VALUES ?c { ${GIVEN_NAME_CLASSES} } ?x wdt:P31 ?c. ?x @${lang}@rdfs:label ?l }`));
    given = given.concat(await sparql(`SELECT ?l WHERE { VALUES ?c { ${GIVEN_NAME_CLASSES} } ?x wdt:P31 ?c. ?x @${lang}@skos:altLabel ?l }`));
  }
  write("given-names.txt", ["Given names. Source: Wikidata (CC0) — labels and English aliases of given-name items."], cleanNames(given));

  // ---- Surnames
  let surnames: string[] = [];
  for (const lang of ["en", "mul"]) surnames = surnames.concat(await sparql(`SELECT ?l WHERE { ?x wdt:P31 wd:Q101352. ?x @${lang}@rdfs:label ?l }`));
  write("surnames.txt", ["Surnames. Source: Wikidata family names (CC0)."], cleanNames(surnames));

  // ---- Places (used only to stop place names being read as first names)
  const cities = unzip(await download("https://download.geonames.org/export/dump/cities15000.zip"), "cities15000.txt")
    .toString("utf-8")
    .split("\n")
    .flatMap((line) => line.split("\t").slice(1, 3)); // name, asciiname
  const regions = (await download("https://download.geonames.org/export/dump/admin1CodesASCII.txt")).toString("utf-8").split("\n").map((l) => l.split("\t")[2]);
  const countries = (await download("https://download.geonames.org/export/dump/countryInfo.txt"))
    .toString("utf-8")
    .split("\n")
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => l.split("\t")[4]);
  write(
    "places.txt",
    ["Place names: cities with population >= 15,000, first-level regions and countries.", "Source: GeoNames (geonames.org), CC BY 4.0."],
    cities.concat(regions, countries).map((v) => v?.trim()).filter((v): v is string => !!v && LATIN_RE.test(v)),
  );
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
