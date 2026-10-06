import type { PIIMatch } from './types.js';

/**
 * Method preference score: higher score indicates higher priority
 * when resolving conflicts between different detection methods.
 */
function getMethodScore(match: PIIMatch): number {
  let score = match.confidence ?? 0.8;
  // Regex is typically deterministic and authoritative for structured patterns
  if (match.method === 'regex') {
    score += 0.05;
  }
  return score;
}

/**
 * Normalizes, deduplicates, and validates PII matches against the original text.
 *
 * Conflict resolution rules:
 * 1. Exact duplicate span (same start, end): Keep the match with higher confidence / deterministic method.
 * 2. Nested / enclosing span (match B is completely contained inside match A):
 *    The enclosing (longer) match takes precedence (e.g., PHONE absorbs nested CARDINAL tokens; EMAIL absorbs PERSON tokens).
 * 3. Partial overlap: Keep the longer span. If equal, prefer higher confidence / regex method.
 * 4. Verification: Guarantees that `text.slice(start, end) === value` for every returned match.
 *
 * @param matches Raw matches from one or more detection engines
 * @param text The original input text
 * @returns Deduplicated, validated, and sorted PIIMatch array
 */
export function normalizeMatches(matches: PIIMatch[], text: string): PIIMatch[] {
  if (!matches || matches.length === 0) {
    return [];
  }

  // Filter out invalid spans and ensure substring integrity
  const validMatches = matches.filter((m) => {
    if (m.start < 0 || m.end > text.length || m.start >= m.end) {
      return false;
    }
    // Strict offset check
    return text.slice(m.start, m.end) === m.value;
  });

  // Sort matches:
  // 1. By start offset ascending
  // 2. By length descending (longer matches come first)
  // 3. By method score descending
  validMatches.sort((a, b) => {
    if (a.start !== b.start) {
      return a.start - b.start;
    }
    const lenA = a.end - a.start;
    const lenB = b.end - b.start;
    if (lenA !== lenB) {
      return lenB - lenA; // Longer first
    }
    return getMethodScore(b) - getMethodScore(a);
  });

  const deduplicated: PIIMatch[] = [];

  for (const candidate of validMatches) {
    let conflict = false;

    for (let i = 0; i < deduplicated.length; i++) {
      const existing = deduplicated[i];
      if (!existing) continue;

      // Check for overlap: start < existing.end && end > existing.start
      const overlaps =
        candidate.start < existing.end && candidate.end > existing.start;

      if (overlaps) {
        conflict = true;

        // Exact match span
        if (candidate.start === existing.start && candidate.end === existing.end) {
          if (getMethodScore(candidate) > getMethodScore(existing)) {
            deduplicated[i] = candidate;
          }
          break;
        }

        // Nested span: candidate is completely inside existing
        if (candidate.start >= existing.start && candidate.end <= existing.end) {
          // Existing already covers candidate; candidate is dropped
          break;
        }

        // Enclosing span: candidate completely encloses existing
        if (candidate.start <= existing.start && candidate.end >= existing.end) {
          // Replace existing with the larger enclosing candidate
          deduplicated[i] = candidate;
          break;
        }

        // Partial overlap: choose longer match or higher score
        const candLen = candidate.end - candidate.start;
        const existLen = existing.end - existing.start;
        if (
          candLen > existLen ||
          (candLen === existLen && getMethodScore(candidate) > getMethodScore(existing))
        ) {
          deduplicated[i] = candidate;
        }
        break;
      }
    }

    if (!conflict) {
      deduplicated.push(candidate);
    }
  }

  // Final sort by start index ascending
  deduplicated.sort((a, b) => a.start - b.start);

  return deduplicated;
}
