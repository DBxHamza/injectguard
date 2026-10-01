/**
 * Shared text helpers: Unicode hygiene, offset-preserving normalisation,
 * chunking and span arithmetic.
 *
 * The single most important function here is `normalizeWithMap`. Attackers
 * defeat naive regex filters by splitting keywords with zero-width characters
 * ("i<U+200B>gnore previous instructions"), by using odd whitespace, or by
 * mixing case. We therefore match patterns against a *normalised* copy of the
 * text, but keep a per-character index map so every match can be reported at
 * its exact offset in the ORIGINAL input. Callers never have to care that the
 * match happened on a transformed string.
 */

/** Zero-width and invisible formatting characters. */
export const ZERO_WIDTH_CHARS = [
  '​', // zero width space
  '‌', // zero width non-joiner
  '‍', // zero width joiner
  '⁠', // word joiner
  '﻿', // zero width no-break space / BOM
  '­', // soft hyphen
  '᠎', // mongolian vowel separator
];

/** Bidirectional control characters (RLO/LRO overrides, isolates, embeddings). */
export const BIDI_CHARS = [
  '‪', '‫', '‬', '‭', '‮',
  '⁦', '⁧', '⁨', '⁩',
  '‎', '‏', '؜',
];

export const ZERO_WIDTH_RE = new RegExp(`[${ZERO_WIDTH_CHARS.join('')}]`, 'gu');
export const BIDI_RE = new RegExp(`[${BIDI_CHARS.join('')}]`, 'gu');

/** Unicode "tag" block, used to smuggle invisible ASCII into text. */
export const TAG_BLOCK_RE = /[\u{e0000}-\u{e007f}]/gu;

/** Characters stripped before pattern matching because they carry no meaning. */
const INVISIBLE_RE = new RegExp(
  `^(?:[${ZERO_WIDTH_CHARS.join('')}${BIDI_CHARS.join('')}]|[\\u{e0000}-\\u{e007f}])$`,
  'u',
);

/**
 * Homoglyph folding: a handful of look-alike characters commonly used to slip
 * past ASCII-only regexes. Kept deliberately 1:1 so the offset map stays exact.
 */
const HOMOGLYPHS = new Map(Object.entries({
  // Cyrillic look-alikes
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
  'у': 'y', 'х': 'x', 'і': 'i', 'һ': 'h', 'ԁ': 'd',
  // Greek look-alikes
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v',
  // Fullwidth Latin letters
  ...Object.fromEntries(
    Array.from({ length: 26 }, (_, i) => [
      String.fromCharCode(0xff41 + i),
      String.fromCharCode(0x61 + i),
    ]),
  ),
  // Typographic punctuation that breaks naive word boundaries
  '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-',
  '‘': "'", '’': "'", '“': '"', '”': '"', ' ': ' ',
  '′': "'", '″': '"', '：': ':', '，': ',', '．': '.',
}));

/**
 * Normalise `text` for pattern matching while recording where every surviving
 * character came from.
 *
 * @param {string} text
 * @returns {{normalized: string, map: number[], length: number}}
 *   `map[i]` is the index in `text` of `normalized[i]`. `map` carries one extra
 *   trailing entry equal to `text.length` so an exclusive end offset can always
 *   be looked up as `map[end]`.
 */
export function normalizeWithMap(text) {
  const src = String(text);
  const out = [];
  const map = [];
  let lastWasSpace = false;

  for (let i = 0; i < src.length; i += 1) {
    const codePoint = src.codePointAt(i);
    const char = String.fromCodePoint(codePoint);
    const advance = char.length - 1; // 1 for astral characters

    if (INVISIBLE_RE.test(char)) {
      i += advance;
      continue;
    }

    const mapped = (HOMOGLYPHS.get(char) ?? char).toLowerCase();

    // Collapse every run of whitespace to a single space.
    if (/\s/u.test(mapped)) {
      if (!lastWasSpace) {
        lastWasSpace = true;
        out.push(' ');
        map.push(i);
      }
      i += advance;
      continue;
    }

    lastWasSpace = false;
    // A fold may yield several chars; point each at the same source offset.
    for (const piece of mapped) {
      out.push(piece);
      map.push(i);
    }
    i += advance;
  }

  map.push(src.length);
  return { normalized: out.join(''), map, length: src.length };
}

/**
 * Translate a [start, end) range on a normalised string back to the original.
 * @returns {{start: number, end: number}}
 */
export function mapRange(map, start, end) {
  if (!map || map.length === 0) return { start: 0, end: 0 };
  const last = map.length - 1;
  const startIdx = Math.max(0, Math.min(start, last));
  const originalStart = map[startIdx];
  // `end` is exclusive, so resolve the offset just past the last kept char.
  const endIdx = Math.max(0, Math.min(Math.max(start, end - 1) + 1, last));
  const originalEnd = map[endIdx];
  return {
    start: originalStart,
    end: Math.max(originalEnd, originalStart + 1),
  };
}

/**
 * Rough token estimate without a tokeniser. ASCII averages ~4 chars/token;
 * Urdu/Arabic script is far less efficient under BPE, so non-ASCII characters
 * are weighted more heavily. Deliberately conservative (over-estimates) so
 * chunks stay inside the model context window.
 */
export function estimateTokens(text) {
  const str = String(text);
  let ascii = 0;
  let wide = 0;
  for (const char of str) {
    if (char.codePointAt(0) < 128) ascii += 1;
    else wide += 1;
  }
  return Math.ceil(ascii / 4 + wide / 1.5);
}

/**
 * Split text into overlapping chunks of about `maxTokens` tokens, preferring
 * paragraph then sentence then word boundaries. Offsets are absolute.
 *
 * @returns {Array<{text: string, start: number, end: number, index: number}>}
 */
export function chunkText(text, { maxTokens = 1500, overlapTokens = 150 } = {}) {
  const src = String(text);
  if (src.length === 0) return [];
  if (estimateTokens(src) <= maxTokens) {
    return [{ text: src, start: 0, end: src.length, index: 0 }];
  }

  // Characters per chunk, derived from the same weighting as estimateTokens.
  const density = estimateTokens(src) / src.length; // tokens per char
  const targetChars = Math.max(200, Math.floor(maxTokens / density));
  const overlapChars = Math.max(
    0,
    Math.min(Math.floor(overlapTokens / density), Math.floor(targetChars / 2)),
  );

  const chunks = [];
  let cursor = 0;
  let index = 0;

  while (cursor < src.length) {
    let end = Math.min(src.length, cursor + targetChars);

    if (end < src.length) {
      // Walk back to the nicest boundary within the last quarter of the chunk.
      const floor = cursor + Math.floor(targetChars * 0.75);
      const window = src.slice(floor, end);
      const candidates = [
        window.lastIndexOf('\n\n'),
        window.lastIndexOf('\n'),
        window.lastIndexOf('. '),
        window.lastIndexOf('۔'), // Urdu full stop
        window.lastIndexOf(' '),
      ];
      const best = candidates.find((pos) => pos > 0);
      if (best !== undefined) end = floor + best + 1;
    }

    chunks.push({ text: src.slice(cursor, end), start: cursor, end, index });
    index += 1;

    if (end >= src.length) break;
    const next = end - overlapChars;
    cursor = next > cursor ? next : end;
  }

  return chunks;
}

/** Convert an offset in the original string into normalised-string space. */
function toNormalizedIndex(map, offset) {
  for (let i = 0; i < map.length; i += 1) if (map[i] >= offset) return i;
  return 0;
}

/**
 * Locate `needle` inside `haystack`, tolerating whitespace and case
 * differences - the LLM often paraphrases spacing when echoing a span back.
 *
 * Strategy, cheapest first:
 *   1. exact match
 *   2. case-insensitive match
 *   3. match on the whitespace/invisible-normalised form, offsets mapped back
 *   4. leading-word anchor, which survives truncation and punctuation drift
 *
 * @returns {{start: number, end: number, exact: boolean} | null}
 */
export function findSpan(haystack, needle, fromIndex = 0) {
  const hay = String(haystack);
  const raw = String(needle ?? '').trim();
  if (raw.length < 3) return null;

  const exact = hay.indexOf(raw, fromIndex);
  if (exact !== -1) return { start: exact, end: exact + raw.length, exact: true };

  const lowerHit = hay.toLowerCase().indexOf(raw.toLowerCase(), fromIndex);
  if (lowerHit !== -1) return { start: lowerHit, end: lowerHit + raw.length, exact: true };

  const { normalized, map } = normalizeWithMap(hay);
  const normNeedle = normalizeWithMap(raw).normalized.trim();
  if (normNeedle.length < 3) return null;

  const hit = normalized.indexOf(normNeedle, toNormalizedIndex(map, fromIndex));
  if (hit !== -1) {
    return { ...mapRange(map, hit, hit + normNeedle.length), exact: false };
  }

  const words = normNeedle.split(' ').filter(Boolean);
  for (let take = Math.min(8, words.length); take >= 3; take -= 1) {
    const probe = words.slice(0, take).join(' ');
    const anchor = normalized.indexOf(probe);
    if (anchor !== -1) {
      const range = mapRange(map, anchor, anchor + Math.max(probe.length, normNeedle.length));
      return { start: range.start, end: Math.min(hay.length, range.end), exact: false };
    }
  }

  return null;
}

/**
 * Merge overlapping or adjacent spans, keeping the highest weight and the
 * union of rule and layer names. Input spans are not mutated.
 */
export function mergeSpans(spans, { gap = 0 } = {}) {
  const valid = (spans ?? [])
    .filter((s) => s && Number.isFinite(s.start) && Number.isFinite(s.end) && s.end > s.start)
    .map((s) => ({ ...s }))
    .sort((a, b) => a.start - b.start || b.end - a.end);

  const merged = [];
  for (const span of valid) {
    const prev = merged[merged.length - 1];
    if (prev && span.start <= prev.end + gap) {
      prev.end = Math.max(prev.end, span.end);
      prev.weight = Math.max(prev.weight ?? 0, span.weight ?? 0);
      prev.rules = [...new Set([
        ...(prev.rules ?? []),
        ...(span.rules ?? []),
        span.rule,
      ].filter(Boolean))];
      prev.layers = [...new Set([
        ...(prev.layers ?? []),
        ...(span.layers ?? []),
        span.layer,
      ].filter(Boolean))];
    } else {
      merged.push({
        ...span,
        rules: [...new Set([...(span.rules ?? []), span.rule].filter(Boolean))],
        layers: [...new Set([...(span.layers ?? []), span.layer].filter(Boolean))],
      });
    }
  }
  return merged;
}

/** Truncate for log output, collapsing newlines. */
export function preview(text, max = 90) {
  const flat = String(text).replace(/\s+/gu, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, max - 1)}…`;
}

/** True when the string contains Urdu/Arabic-script characters. */
export function hasUrduScript(text) {
  return /[؀-ۿݐ-ݿﭐ-﷿ﹰ-﻿]/u.test(String(text));
}
