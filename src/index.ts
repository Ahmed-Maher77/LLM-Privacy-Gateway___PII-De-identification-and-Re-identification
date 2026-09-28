import { detectPII, maskPII } from "./pii-masker";
import fs from "node:fs";

const text = fs.readFileSync("test_data/mockup_interview.txt", "utf-8");

const config = {
  EMAIL: true,
  URL: true,
  DATE: true,
  MONEY: false,
};

console.log("=== ORIGINAL ===");
console.log(text);

console.log("\n=== DETECTED PII ===");

const matches = detectPII(text, config);

for (const match of matches) {
  console.log(match);
}

console.log("\n=== MASKED ===");
console.log(maskPII(text, config));