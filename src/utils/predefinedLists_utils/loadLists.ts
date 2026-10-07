import path from "node:path";
import fs from 'node:fs';
import { ListFile, Lists } from "../../pii/types";
import { stringFromEnv } from "../envGetter";
import { desiredRules, key, ListError, undesiredKeys } from "./predefined_helpers";


const CONFIG_DIR = path.resolve(__dirname, "../../../config");

// ========= Read a pre-defined list file =========
function readList(envName: string, fallback: string): ListFile {
    const file = path.join(CONFIG_DIR, stringFromEnv(envName, fallback));
    if (!fs.existsSync(file)) throw new ListError(`${file} is missing (${envName} in .env names it).`);
    try {
        // A BOM (e.g. from Windows editors) is not JSON
        return { json: JSON.parse(fs.readFileSync(file, "utf-8").replace(/^﻿/, "")), file };
    } catch {
        throw new ListError(`${file} is not valid JSON.`);
    }
}


// ======== Load both lists, once per process =========
let lists: Lists | undefined;

function load(): Lists {
    return (lists ??= {
        desired: desiredRules(readList("DESIRED_PREDEFINED_LIST", "desired-predefined-list.json")),
        undesired: undesiredKeys(readList("UNDESIRED_PREDEFINED_LIST", "undesired-predefined-list.json")),
    });
}

// ======== Is a value on the undesired list? =========
function isUndesired(value: string): boolean {
    return load().undesired.has(key(value));
}


export {
    load,
    isUndesired
}