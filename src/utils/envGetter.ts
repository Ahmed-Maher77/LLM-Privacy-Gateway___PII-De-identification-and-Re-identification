import "dotenv/config";

// ========== get a positive number from .env ==========
function numberFromEnv(name: string, fallback: number): number {
    const value = Number(process.env[name] ?? fallback);
    if (!Number.isFinite(value) || value <= 0) throw new Error(`${name} must be a positive number.`);
    return value;
}


// ========= get a string value from .env =========
function stringFromEnv(name: string, fallback: string): string {
    const value = process.env[name] ?? fallback;
    if (!value) throw new Error(`${name} is missing.`);
    return value;
}


export {
    numberFromEnv,
    stringFromEnv
}