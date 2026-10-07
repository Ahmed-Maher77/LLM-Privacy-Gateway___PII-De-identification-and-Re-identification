// Escape a literal so it matches itself inside a RegExp
export const escapeRegex = (v: string) => v.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Match any of the alternatives as a whole word: not inside a longer run of letters, digits or underscores
export const wholeWords = (alternatives: string[], flags: string) =>
  new RegExp(`(?<![\\p{L}\\p{N}_])(?:${alternatives.join("|")})(?![\\p{L}\\p{N}_])`, flags);
