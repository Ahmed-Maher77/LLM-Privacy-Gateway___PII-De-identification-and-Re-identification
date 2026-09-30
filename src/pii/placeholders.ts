// Placeholders for redacted spans

// Normalise a value for use as a key in the `Placeholders` class
function valueKey(text: string): string {
    return text.toLowerCase().replace(/['’]s$/, "").replace(/[\s.-]+/g, "");
}

// Hands out <TYPE_N> placeholders for one document
export class Placeholders {
    private readonly numbers = new Map<string, Map<string, number>>();

    for(type: string, text: string): string {
        let byValue = this.numbers.get(type);
        if (!byValue) this.numbers.set(type, (byValue = new Map()));
        const key = valueKey(text);
        let n = byValue.get(key);
        if (n === undefined) byValue.set(key, (n = byValue.size + 1));
        return `<${type}_${n}>`;
    }
}
