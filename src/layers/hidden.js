/**
 * LAYER 1 - hidden and obfuscated content extraction.
 *
 * Prompt injection against an agent is usually invisible to the human who
 * approved the page. This layer answers one question: "what does this document
 * say that a human reader would never see?" It returns both the hidden
 * fragments (so layers 2 and 3 can judge them) and the visible text (so the
 * agent can still be given something useful).
 *
 * What it finds:
 *   - CSS-hidden elements: display:none, visibility:hidden, opacity:0,
 *     font-size:0, colour equal to its background (white-on-white), plus the
 *     common off-screen tricks (text-indent:-9999px, clip, 0x0 + overflow)
 *   - the `hidden` attribute and aria-hidden="true"
 *   - HTML comments
 *   - text carried in alt / title / aria-label attributes
 *   - zero-width and bidi-control characters
 *   - base64 blobs, decoded and re-scanned
 *
 * Styles are resolved from inline `style` attributes AND from rules inside
 * <style> blocks, because `<p class="x">` + `.x{display:none}` is the form the
 * attack actually takes in the wild. Selector matching is deliberately
 * permissive (it matches the right-most compound selector and ignores
 * combinators), which can over-match; for a scanner, over-reporting hidden text
 * is the safe direction to err in.
 *
 * Every finding carries `start`/`end` offsets into the ORIGINAL input so that
 * guard.sanitize() can excise exactly the bytes involved.
 */

import {
  ZERO_WIDTH_RE,
  BIDI_RE,
  TAG_BLOCK_RE,
  preview,
} from '../util/text.js';

/* ------------------------------------------------------------------ *
 * HTML tokenizer
 * ------------------------------------------------------------------ */

const RAW_TEXT_ELEMENTS = new Set(['script', 'style', 'textarea', 'title']);
const VOID_ELEMENTS = new Set([
  'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link',
  'meta', 'param', 'source', 'track', 'wbr',
]);
/** Elements whose text is never shown to a reader. */
const INVISIBLE_ELEMENTS = new Set(['script', 'style', 'template', 'noscript', 'head']);
/** Block-level elements that should produce a line break in visible text. */
const BLOCK_ELEMENTS = new Set([
  'address', 'article', 'aside', 'blockquote', 'br', 'div', 'dd', 'dl', 'dt',
  'fieldset', 'figcaption', 'figure', 'footer', 'form', 'h1', 'h2', 'h3', 'h4',
  'h5', 'h6', 'header', 'hr', 'li', 'main', 'nav', 'ol', 'p', 'pre', 'section',
  'table', 'tr', 'td', 'th', 'ul',
]);

const ATTR_RE = /([^\s"'=/<>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

function parseAttributes(source) {
  const attrs = {};
  ATTR_RE.lastIndex = 0;
  let match = ATTR_RE.exec(source);
  while (match) {
    const name = match[1].toLowerCase();
    const value = match[2] ?? match[3] ?? match[4] ?? '';
    if (!(name in attrs)) attrs[name] = value;
    match = ATTR_RE.exec(source);
  }
  return attrs;
}

/**
 * Tokenize HTML permissively. Never throws: anything unparseable becomes text.
 * @returns {Array<object>} tokens with absolute `start`/`end` offsets
 */
export function tokenizeHTML(html) {
  const src = String(html);
  const tokens = [];
  let i = 0;

  const pushText = (start, end) => {
    if (end > start) tokens.push({ type: 'text', start, end, raw: src.slice(start, end) });
  };

  while (i < src.length) {
    const lt = src.indexOf('<', i);
    if (lt === -1) {
      pushText(i, src.length);
      break;
    }
    pushText(i, lt);

    // Comment
    if (src.startsWith('<!--', lt)) {
      let end = src.indexOf('-->', lt + 4);
      const closed = end !== -1;
      end = closed ? end + 3 : src.length;
      tokens.push({
        type: 'comment',
        start: lt,
        end,
        raw: src.slice(lt, end),
        text: src.slice(lt + 4, closed ? end - 3 : end),
      });
      i = end;
      continue;
    }

    // CDATA / doctype / processing instruction
    if (src.startsWith('<!', lt) || src.startsWith('<?', lt)) {
      let end = src.indexOf('>', lt);
      end = end === -1 ? src.length : end + 1;
      tokens.push({ type: 'directive', start: lt, end, raw: src.slice(lt, end) });
      i = end;
      continue;
    }

    const isEnd = src[lt + 1] === '/';
    const nameMatch = /^[a-zA-Z][a-zA-Z0-9:_-]*/.exec(src.slice(lt + (isEnd ? 2 : 1)));
    if (!nameMatch) {
      // A bare "<" in text.
      pushText(lt, lt + 1);
      i = lt + 1;
      continue;
    }

    let gt = lt;
    let inQuote = null;
    while (gt < src.length) {
      const ch = src[gt];
      if (inQuote) {
        if (ch === inQuote) inQuote = null;
      } else if (ch === '"' || ch === "'") {
        inQuote = ch;
      } else if (ch === '>') {
        break;
      }
      gt += 1;
    }
    const tagEnd = gt < src.length ? gt + 1 : src.length;
    const name = nameMatch[0].toLowerCase();
    const inner = src.slice(lt + (isEnd ? 2 : 1) + name.length, gt);

    if (isEnd) {
      tokens.push({ type: 'endtag', name, start: lt, end: tagEnd, raw: src.slice(lt, tagEnd) });
      i = tagEnd;
      continue;
    }

    const selfClosing = /\/\s*$/.test(inner) || VOID_ELEMENTS.has(name);
    tokens.push({
      type: 'tag',
      name,
      attrs: parseAttributes(inner),
      selfClosing,
      start: lt,
      end: tagEnd,
      raw: src.slice(lt, tagEnd),
      innerStart: tagEnd,
    });
    i = tagEnd;

    // Raw-text elements swallow everything up to their close tag.
    if (!selfClosing && RAW_TEXT_ELEMENTS.has(name)) {
      const closeRe = new RegExp(`</${name}\\s*>`, 'i');
      const rest = src.slice(tagEnd);
      const found = closeRe.exec(rest);
      const rawEnd = found ? tagEnd + found.index : src.length;
      if (rawEnd > tagEnd) {
        tokens.push({
          type: 'rawtext',
          owner: name,
          start: tagEnd,
          end: rawEnd,
          raw: src.slice(tagEnd, rawEnd),
        });
      }
      i = rawEnd;
    }
  }

  return tokens;
}

/* ------------------------------------------------------------------ *
 * Entities
 * ------------------------------------------------------------------ */

const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  copy: '©', reg: '®', hellip: '…', mdash: '—',
  ndash: '–', lsquo: '‘', rsquo: '’', ldquo: '“',
  rdquo: '”', middot: '·', bull: '•', deg: '°',
  zwnj: '‌', zwj: '‍', shy: '­', rlo: '‮',
};

export function decodeEntities(text) {
  return String(text).replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]{1,31});/g, (whole, body) => {
    if (body[0] === '#') {
      const isHex = body[1] === 'x' || body[1] === 'X';
      const code = Number.parseInt(isHex ? body.slice(2) : body.slice(1), isHex ? 16 : 10);
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole;
      try {
        return String.fromCodePoint(code);
      } catch {
        return whole;
      }
    }
    const named = NAMED_ENTITIES[body.toLowerCase()];
    return named ?? whole;
  });
}

/* ------------------------------------------------------------------ *
 * Colours
 * ------------------------------------------------------------------ */

const NAMED_COLORS = {
  white: [255, 255, 255], black: [0, 0, 0], red: [255, 0, 0],
  green: [0, 128, 0], blue: [0, 0, 255], yellow: [255, 255, 0],
  gray: [128, 128, 128], grey: [128, 128, 128], silver: [192, 192, 192],
  whitesmoke: [245, 245, 245], ghostwhite: [248, 248, 255],
  snow: [255, 250, 250], ivory: [255, 255, 240], floralwhite: [255, 250, 240],
  azure: [240, 255, 255], aliceblue: [240, 248, 255], lightgray: [211, 211, 211],
  lightgrey: [211, 211, 211], gainsboro: [220, 220, 220], linen: [250, 240, 230],
  seashell: [255, 245, 238], mintcream: [245, 255, 250], transparent: null,
};

/** @returns {[number, number, number] | null} null means transparent/unknown */
export function parseColor(value) {
  if (!value) return null;
  const raw = String(value).trim().toLowerCase();

  if (raw in NAMED_COLORS) return NAMED_COLORS[raw];

  const hex = /^#([0-9a-f]{3,8})$/.exec(raw);
  if (hex) {
    const digits = hex[1];
    if (digits.length === 3 || digits.length === 4) {
      const [r, g, b] = [...digits.slice(0, 3)].map((d) => Number.parseInt(d + d, 16));
      if (digits.length === 4 && Number.parseInt(digits[3] + digits[3], 16) === 0) return null;
      return [r, g, b];
    }
    if (digits.length === 6 || digits.length === 8) {
      const r = Number.parseInt(digits.slice(0, 2), 16);
      const g = Number.parseInt(digits.slice(2, 4), 16);
      const b = Number.parseInt(digits.slice(4, 6), 16);
      if (digits.length === 8 && Number.parseInt(digits.slice(6, 8), 16) === 0) return null;
      return [r, g, b];
    }
    return null;
  }

  const fn = /^rgba?\(\s*([^)]+)\)$/.exec(raw);
  if (fn) {
    const parts = fn[1].split(/[\s,/]+/).filter(Boolean);
    const nums = parts.map((p) => (p.endsWith('%')
      ? (Number.parseFloat(p) / 100) * 255
      : Number.parseFloat(p)));
    if (nums.length >= 3 && nums.slice(0, 3).every(Number.isFinite)) {
      if (nums.length >= 4 && Number.isFinite(nums[3]) && nums[3] <= 0.08) return null;
      return [Math.round(nums[0]), Math.round(nums[1]), Math.round(nums[2])];
    }
  }

  const hsl = /^hsla?\(\s*([^)]+)\)$/.exec(raw);
  if (hsl) {
    const parts = hsl[1].split(/[\s,/]+/).filter(Boolean).map((p) => Number.parseFloat(p));
    if (parts.length >= 3 && parts.slice(0, 3).every(Number.isFinite)) {
      if (parts.length >= 4 && parts[3] <= 0.08) return null;
      return hslToRgb(parts[0], parts[1] / 100, parts[2] / 100);
    }
  }

  return null;
}

function hslToRgb(hDeg, s, l) {
  const h = ((hDeg % 360) + 360) % 360 / 360;
  if (s === 0) {
    const v = Math.round(l * 255);
    return [v, v, v];
  }
  const q = l < 0.5 ? l * (1 + s) : l + s - l * s;
  const p = 2 * l - q;
  const channel = (t0) => {
    let t = t0;
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  return [
    Math.round(channel(h + 1 / 3) * 255),
    Math.round(channel(h) * 255),
    Math.round(channel(h - 1 / 3) * 255),
  ];
}

/** Perceptual-ish distance; small values mean the text is unreadable. */
export function colorDistance(a, b) {
  if (!a || !b) return Infinity;
  const dr = a[0] - b[0];
  const dg = a[1] - b[1];
  const db = a[2] - b[2];
  // Weighted to human luminance sensitivity.
  return Math.sqrt(0.299 * dr * dr + 0.587 * dg * dg + 0.114 * db * db);
}

/** Below this, foreground and background are effectively the same colour. */
const SAME_COLOR_THRESHOLD = 12;

/* ------------------------------------------------------------------ *
 * CSS
 * ------------------------------------------------------------------ */

/**
 * Collect declaration blocks from a stylesheet, including those nested inside
 * at-rules such as @media. Returns rules in source order.
 * @returns {Array<{selectors: string[], decls: object, order: number}>}
 */
export function parseStylesheet(css) {
  const src = String(css).replace(/\/\*[\s\S]*?\*\//g, ' ');
  const rules = [];
  let order = 0;

  const readBlock = (from) => {
    let depth = 0;
    for (let j = from; j < src.length; j += 1) {
      if (src[j] === '{') depth += 1;
      else if (src[j] === '}') {
        depth -= 1;
        if (depth === 0) return j;
      }
    }
    return src.length;
  };

  const walk = (text, offset) => {
    let cursor = 0;
    while (cursor < text.length) {
      const brace = text.indexOf('{', cursor);
      if (brace === -1) break;
      const prelude = text.slice(cursor, brace).trim();
      const absBrace = offset + brace;
      const close = readBlock(absBrace);
      const body = src.slice(absBrace + 1, close);

      if (prelude.startsWith('@')) {
        // Conditional group rules contain nested rules; descend into them.
        if (/^@(media|supports|layer|container|scope)/i.test(prelude)) {
          walk(body, absBrace + 1);
        }
      } else if (prelude) {
        rules.push({
          selectors: prelude.split(',').map((s) => s.trim()).filter(Boolean),
          decls: parseDeclarations(body),
          order: order += 1,
        });
      }
      cursor = close - offset + 1;
      if (cursor <= brace) break;
    }
  };

  walk(src, 0);
  return rules;
}

export function parseDeclarations(text) {
  const decls = {};
  for (const part of String(text).split(';')) {
    const colon = part.indexOf(':');
    if (colon === -1) continue;
    const prop = part.slice(0, colon).trim().toLowerCase();
    const value = part.slice(colon + 1).replace(/!important/i, '').trim();
    if (prop) decls[prop] = value;
  }
  return decls;
}

/**
 * Match a selector against an element. Combinators are ignored: only the
 * right-most compound selector is tested. See the module comment on why this
 * errs toward over-matching.
 * @returns {number | null} specificity, or null when it does not match
 */
export function matchSelector(selector, el) {
  // Drop pseudo-elements/classes we cannot evaluate, but reject the ones that
  // mean "not normally rendered" would be wrong to assume.
  const cleaned = selector.replace(/::?[a-z-]+(\([^)]*\))?/gi, '');
  const compounds = cleaned.trim().split(/[\s>+~]+/).filter(Boolean);
  const target = compounds[compounds.length - 1];
  if (!target) return null;

  let specificity = 0;
  const parts = target.match(/[#.]?[\w-]+|\[[^\]]*\]|\*/g);
  if (!parts) return null;

  for (const part of parts) {
    if (part === '*') continue;
    if (part.startsWith('#')) {
      if (el.attrs.id !== part.slice(1)) return null;
      specificity += 100;
    } else if (part.startsWith('.')) {
      if (!el.classList.includes(part.slice(1))) return null;
      specificity += 10;
    } else if (part.startsWith('[')) {
      const attr = /\[\s*([\w-]+)\s*(?:([~^$*|]?=)\s*"?([^"\]]*)"?\s*)?\]/.exec(part);
      if (!attr) return null;
      const have = el.attrs[attr[1].toLowerCase()];
      if (have === undefined) return null;
      if (attr[2] && attr[3] !== undefined && !String(have).includes(attr[3])) return null;
      specificity += 10;
    } else {
      if (el.name !== part.toLowerCase()) return null;
      specificity += 1;
    }
  }
  return specificity;
}

/* ------------------------------------------------------------------ *
 * Hidden-style detection
 * ------------------------------------------------------------------ */

function lengthIsZeroish(value) {
  if (value === undefined) return false;
  const m = /^(-?[\d.]+)\s*(px|pt|em|rem|%|ex|ch|vh|vw)?$/.exec(String(value).trim());
  if (!m) return false;
  const n = Number.parseFloat(m[1]);
  if (!Number.isFinite(n)) return false;
  const unit = m[2] ?? 'px';
  if (n === 0) return true;
  // 1px / 0.01em text is not readable either.
  if (unit === 'px' || unit === 'pt') return Math.abs(n) <= 1;
  return Math.abs(n) <= 0.05;
}

function isOffscreen(decls) {
  const reasons = [];
  const indent = decls['text-indent'];
  if (indent && /^-\s*\d{3,}/.test(indent.trim())) reasons.push(`text-indent:${indent}`);

  const position = (decls.position ?? '').toLowerCase();
  if (position === 'absolute' || position === 'fixed') {
    for (const side of ['left', 'top', 'right', 'bottom']) {
      const v = decls[side];
      if (v && /^-\s*\d{3,}/.test(v.trim())) reasons.push(`${side}:${v}`);
    }
  }

  const clip = decls.clip ?? '';
  if (/rect\(\s*0[^)]*\)/.test(clip)) reasons.push(`clip:${clip}`);
  const clipPath = decls['clip-path'] ?? '';
  if (/inset\(\s*(100%|50%)/.test(clipPath)) reasons.push(`clip-path:${clipPath}`);

  const overflow = (decls.overflow ?? '').toLowerCase();
  if ((overflow === 'hidden' || overflow === 'clip')
    && (lengthIsZeroish(decls.height) || lengthIsZeroish(decls.width))) {
    reasons.push(`${lengthIsZeroish(decls.height) ? 'height' : 'width'}:0 + overflow:hidden`);
  }

  if (/scale\(\s*0\s*[,)]/.test(decls.transform ?? '')) reasons.push(`transform:${decls.transform}`);

  return reasons;
}

/**
 * Decide whether an element's own declarations hide its text.
 * @returns {{hidden: boolean, reasons: string[], weight: number}}
 */
export function evaluateVisibility(decls, inheritedBackground) {
  const reasons = [];
  let weight = 0;

  const display = (decls.display ?? '').toLowerCase();
  if (display === 'none') {
    reasons.push('display:none');
    weight = Math.max(weight, 0.45);
  }

  const visibility = (decls.visibility ?? '').toLowerCase();
  if (visibility === 'hidden' || visibility === 'collapse') {
    reasons.push(`visibility:${visibility}`);
    weight = Math.max(weight, 0.45);
  }

  if (decls.opacity !== undefined) {
    const opacity = Number.parseFloat(decls.opacity);
    if (Number.isFinite(opacity) && opacity <= 0.05) {
      reasons.push(`opacity:${decls.opacity}`);
      weight = Math.max(weight, 0.45);
    }
  }

  if (lengthIsZeroish(decls['font-size'])) {
    reasons.push(`font-size:${decls['font-size']}`);
    weight = Math.max(weight, 0.45);
  }

  const color = decls.color;
  if (color !== undefined) {
    const fg = parseColor(color);
    if (fg === null && /transparent/i.test(color)) {
      reasons.push('color:transparent');
      weight = Math.max(weight, 0.45);
    } else if (fg) {
      const bg = parseColor(decls['background-color'] ?? decls.background)
        ?? inheritedBackground
        ?? [255, 255, 255];
      const distance = colorDistance(fg, bg);
      if (distance <= SAME_COLOR_THRESHOLD) {
        const bgHex = `rgb(${bg.join(',')})`;
        reasons.push(`color ${color} matches background ${bgHex}`);
        weight = Math.max(weight, 0.5);
      }
    }
  }

  for (const reason of isOffscreen(decls)) {
    reasons.push(reason);
    weight = Math.max(weight, 0.4);
  }

  return { hidden: reasons.length > 0, reasons, weight };
}

/* ------------------------------------------------------------------ *
 * Base64
 * ------------------------------------------------------------------ */

const BASE64_RE = /[A-Za-z0-9+/]{24,}={0,2}/g;
const BASE64_URL_RE = /[A-Za-z0-9_-]{24,}={0,2}/g;

function looksLikeText(decoded) {
  if (decoded.length < 12) return false;
  let printable = 0;
  for (const ch of decoded) {
    const code = ch.codePointAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code < 127)) printable += 1;
    else if (code >= 0x600 && code <= 0x6ff) printable += 1; // Urdu/Arabic
    else if (code > 0xa0 && code < 0x2500) printable += 1;
  }
  if (printable / decoded.length < 0.85) return false;
  // Require something word-like, so we do not "decode" random identifiers.
  return /[A-Za-z؀-ۿ]{3,}/.test(decoded) && /[\s؀-ۿ]/.test(decoded);
}

function decodeBase64(blob) {
  try {
    const normalized = blob.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
    const buf = Buffer.from(padded, 'base64');
    if (buf.length === 0) return null;
    const text = buf.toString('utf8');
    // Reject lossy decodes (replacement characters mean it was not text).
    if (text.includes('�')) return null;
    return text;
  } catch {
    return null;
  }
}

/**
 * Find base64 blobs in `text` and decode the ones that look like natural
 * language. Offsets are relative to `baseOffset`.
 */
export function findBase64(text, baseOffset = 0, { origin = 'text' } = {}) {
  const findings = [];
  const seen = new Set();

  for (const re of [BASE64_RE, BASE64_URL_RE]) {
    re.lastIndex = 0;
    let match = re.exec(text);
    while (match) {
      const blob = match[0];
      const start = baseOffset + match.index;
      if (!seen.has(start) && (blob.includes('=') || blob.length >= 32)) {
        const decoded = decodeBase64(blob);
        if (decoded && looksLikeText(decoded)) {
          seen.add(start);
          findings.push({
            kind: 'base64',
            detail: `base64 blob of ${blob.length} chars decoded to readable text`,
            origin,
            start,
            end: start + blob.length,
            source: blob,
            text: decoded,
            decoded: true,
            weight: 0.3,
          });
        }
      }
      match = re.exec(text);
    }
  }

  return findings;
}

/* ------------------------------------------------------------------ *
 * Invisible characters
 * ------------------------------------------------------------------ */

function scanInvisibleChars(src) {
  const findings = [];
  const groups = [
    { re: ZERO_WIDTH_RE, kind: 'zero-width', detail: 'zero-width character', weight: 0.25 },
    { re: BIDI_RE, kind: 'bidi-control', detail: 'bidirectional control character', weight: 0.3 },
    { re: TAG_BLOCK_RE, kind: 'unicode-tag', detail: 'Unicode tag-block character', weight: 0.4 },
  ];

  for (const group of groups) {
    group.re.lastIndex = 0;
    const runs = [];
    let match = group.re.exec(src);
    while (match) {
      const last = runs[runs.length - 1];
      if (last && match.index <= last.end + 2) last.end = match.index + match[0].length;
      else runs.push({ start: match.index, end: match.index + match[0].length });
      match = group.re.exec(src);
    }
    for (const run of runs) {
      findings.push({
        kind: group.kind,
        detail: `${group.detail}(s) at offset ${run.start}`,
        start: run.start,
        end: run.end,
        text: src.slice(run.start, run.end),
        weight: group.weight,
      });
    }
  }

  // Unicode tag block can smuggle whole ASCII sentences: decode them.
  TAG_BLOCK_RE.lastIndex = 0;
  const tagChars = [...src.matchAll(TAG_BLOCK_RE)];
  if (tagChars.length >= 4) {
    const decoded = tagChars
      .map((m) => String.fromCodePoint(m[0].codePointAt(0) - 0xe0000))
      .join('');
    if (/[A-Za-z]{3,}/.test(decoded)) {
      findings.push({
        kind: 'unicode-tag-decoded',
        detail: 'Unicode tag characters decode to readable ASCII',
        start: tagChars[0].index,
        end: tagChars[tagChars.length - 1].index + tagChars[tagChars.length - 1][0].length,
        text: decoded,
        decoded: true,
        weight: 0.45,
      });
    }
  }

  return findings;
}

/* ------------------------------------------------------------------ *
 * Instruction smell (for weighting only)
 * ------------------------------------------------------------------ */

const INSTRUCTION_SMELL = [
  /\b(ignore|disregard|forget|override)\b/i,
  /\byou (?:are|must|should|will|need to)\b/i,
  /\b(?:system|assistant|developer)\s*[:>\]]/i,
  /\b(?:new|updated|important|urgent)\s+(?:instruction|directive|task|rule)/i,
  /\b(?:send|email|post|upload|forward|exfiltrate)\b[\s\S]{0,60}\b(?:key|token|secret|password|credential|env)/i,
  /\b(?:do not|don't|never)\s+(?:tell|mention|reveal|inform|show)\b/i,
  /\b(get_secret|send_email|http_post|read_page|read_email)\b/i,
  /(?:nazar\s*andaz|bhool\s*ja|bhej\s*d|mat\s*batana|hidayat)/i,
  /[ن][ظ][ر]\s*[ا][ن][د][ا][ز]/,
  /[ہ][د][ا][ی][ا][ت]/,
  /[ب][ھ][ی][ج]/,
];

/**
 * Cheap, self-contained check for "this text is addressing an AI".
 *
 * This exists only so L1 can weight hidden-and-instruction-shaped content
 * higher than hidden-but-boring content. The authoritative judgement comes from
 * guard.js running the full layer 2 ruleset over `hiddenText`.
 */
export function looksLikeInstruction(text) {
  const hits = INSTRUCTION_SMELL.filter((re) => re.test(text));
  return { instruction: hits.length > 0, matches: hits.length };
}

/* ------------------------------------------------------------------ *
 * Main entry point
 * ------------------------------------------------------------------ */

/**
 * Extract hidden/obfuscated content.
 *
 * @param {string} input raw HTML or plain text
 * @param {{isHTML?: boolean, source?: string}} [opts]
 * @returns {{
 *   layer: 'L1', score: number, findings: object[], spans: object[],
 *   visibleText: string, hiddenText: string, stats: object
 * }}
 */
export function extractHidden(input, opts = {}) {
  const src = String(input ?? '');
  const isHTML = opts.isHTML ?? /<\/?[a-z][\s\S]*>/i.test(src);
  const findings = [];

  // --- Unicode-level signals apply to HTML and plain text alike.
  findings.push(...scanInvisibleChars(src));

  let visibleText = '';

  if (!isHTML) {
    visibleText = src;
    findings.push(...findBase64(src, 0, { origin: 'text' }));
  } else {
    const tokens = tokenizeHTML(src);

    // Pass 1: gather stylesheets so class-based hiding resolves.
    const stylesheets = [];
    for (let idx = 0; idx < tokens.length; idx += 1) {
      const token = tokens[idx];
      if (token.type === 'rawtext' && token.owner === 'style') stylesheets.push(token.raw);
    }
    const rules = stylesheets.length ? parseStylesheet(stylesheets.join('\n')) : [];

    // Pass 2: walk the document with a style stack.
    const stack = [];
    const visibleParts = [];

    const currentHidden = () => stack.find((frame) => frame.hidden);
    const currentBackground = () => {
      for (let i = stack.length - 1; i >= 0; i -= 1) {
        const bg = stack[i].background;
        if (bg) return bg;
      }
      return [255, 255, 255];
    };
    const inInvisibleElement = () => stack.some((frame) => INVISIBLE_ELEMENTS.has(frame.name));

    for (const token of tokens) {
      if (token.type === 'comment') {
        const text = decodeEntities(token.text ?? '');
        if (text.trim().length > 0) {
          const smell = looksLikeInstruction(text);
          findings.push({
            kind: 'html-comment',
            detail: 'content inside an HTML comment',
            start: token.start,
            end: token.end,
            text: text.trim(),
            weight: smell.instruction ? 0.4 : 0.15,
            instruction: smell.instruction,
          });
        }
        findings.push(...findBase64(token.raw, token.start, { origin: 'html-comment' }));
        continue;
      }

      if (token.type === 'rawtext') {
        // <style> and <script> bodies: never visible, but do carry base64.
        findings.push(...findBase64(token.raw, token.start, { origin: token.owner }));
        if (token.owner === 'title' || token.owner === 'textarea') {
          const text = decodeEntities(token.raw);
          if (!currentHidden() && text.trim()) visibleParts.push(text.trim());
        }
        continue;
      }

      if (token.type === 'tag') {
        const attrs = token.attrs ?? {};
        const classList = (attrs.class ?? '').split(/\s+/).filter(Boolean);
        const el = { name: token.name, attrs, classList };

        // Resolve declarations: stylesheet rules by specificity, then inline.
        const matched = [];
        for (const rule of rules) {
          let best = null;
          for (const selector of rule.selectors) {
            const spec = matchSelector(selector, el);
            if (spec !== null && (best === null || spec > best)) best = spec;
          }
          if (best !== null) matched.push({ spec: best, order: rule.order, decls: rule.decls });
        }
        matched.sort((a, b) => a.spec - b.spec || a.order - b.order);

        const decls = {};
        for (const rule of matched) Object.assign(decls, rule.decls);
        Object.assign(decls, parseDeclarations(attrs.style ?? ''));

        const verdict = evaluateVisibility(decls, currentBackground());
        const reasons = [...verdict.reasons];
        let weight = verdict.weight;

        if ('hidden' in attrs) {
          reasons.push('hidden attribute');
          weight = Math.max(weight, 0.4);
        }
        if ((attrs['aria-hidden'] ?? '').toLowerCase() === 'true') {
          reasons.push('aria-hidden="true"');
          weight = Math.max(weight, 0.35);
        }
        if (token.name === 'template') {
          reasons.push('<template> content');
          weight = Math.max(weight, 0.3);
        }

        const inheritedHidden = currentHidden();
        const frame = {
          name: token.name,
          hidden: reasons.length > 0 || Boolean(inheritedHidden),
          ownReasons: reasons,
          reasons: inheritedHidden ? inheritedHidden.reasons : reasons,
          weight: Math.max(weight, inheritedHidden?.weight ?? 0),
          background: parseColor(decls['background-color'] ?? decls.background),
          start: token.end,
          tagStart: token.start,
          collected: [],
          isOwner: reasons.length > 0 && !inheritedHidden,
        };

        // Attribute-borne text: alt / title / aria-label are read by screen
        // readers and by agents, but a sighted reader usually never sees them.
        for (const attrName of ['alt', 'title', 'aria-label', 'aria-description', 'placeholder', 'data-tooltip']) {
          const value = decodeEntities(attrs[attrName] ?? '').trim();
          if (value.length < 4) continue;
          const smell = looksLikeInstruction(value);
          const attrOffset = token.raw.indexOf(attrs[attrName] ?? '');
          findings.push({
            kind: 'attribute-text',
            detail: `text in ${attrName}="..." on <${token.name}>`,
            start: token.start + (attrOffset === -1 ? 0 : attrOffset),
            end: attrOffset === -1
              ? token.end
              : token.start + attrOffset + (attrs[attrName] ?? '').length,
            text: value,
            weight: smell.instruction ? 0.4 : 0.1,
            instruction: smell.instruction,
          });
        }

        findings.push(...findBase64(token.raw, token.start, { origin: `<${token.name}> attribute` }));

        if (!token.selfClosing) stack.push(frame);
        else if (BLOCK_ELEMENTS.has(token.name)) visibleParts.push('\n');

        if (!token.selfClosing && BLOCK_ELEMENTS.has(token.name) && !frame.hidden) {
          visibleParts.push('\n');
        }
        continue;
      }

      if (token.type === 'endtag') {
        // Unwind to the matching open tag, tolerating unclosed elements.
        const depth = stack.map((f) => f.name).lastIndexOf(token.name);
        if (depth !== -1) {
          const closing = stack.splice(depth);
          for (const frame of closing) {
            if (frame.isOwner) {
              const text = frame.collected.join('').replace(/[ \t]+/g, ' ').trim();
              if (text.length > 0) {
                const smell = looksLikeInstruction(text);
                findings.push({
                  kind: 'css-hidden',
                  detail: `<${frame.name}> hidden by ${frame.ownReasons.join('; ')}`,
                  start: frame.tagStart,
                  end: token.end,
                  text,
                  weight: smell.instruction
                    ? Math.min(0.85, frame.weight + 0.35)
                    : frame.weight,
                  instruction: smell.instruction,
                  reasons: frame.ownReasons,
                });
              }
            }
          }
        }
        if (BLOCK_ELEMENTS.has(token.name) && !currentHidden()) visibleParts.push('\n');
        continue;
      }

      if (token.type === 'text') {
        const decoded = decodeEntities(token.raw);
        const hiddenFrame = currentHidden();
        if (hiddenFrame) {
          for (const frame of stack) if (frame.isOwner || frame === hiddenFrame) frame.collected.push(decoded);
          findings.push(...findBase64(token.raw, token.start, { origin: 'hidden text' }));
        } else if (!inInvisibleElement()) {
          visibleParts.push(decoded);
          findings.push(...findBase64(token.raw, token.start, { origin: 'visible text' }));
        }
      }
    }

    // Close out any element left open at EOF.
    for (const frame of stack) {
      if (!frame.isOwner) continue;
      const text = frame.collected.join('').replace(/[ \t]+/g, ' ').trim();
      if (!text) continue;
      const smell = looksLikeInstruction(text);
      findings.push({
        kind: 'css-hidden',
        detail: `<${frame.name}> hidden by ${frame.ownReasons.join('; ')} (unclosed)`,
        start: frame.tagStart,
        end: src.length,
        text,
        weight: smell.instruction ? Math.min(0.85, frame.weight + 0.35) : frame.weight,
        instruction: smell.instruction,
        reasons: frame.ownReasons,
      });
    }

    visibleText = visibleParts
      .join('')
      .replace(/[ \t ]+/g, ' ')
      .replace(/ ?\n ?/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  // Base64 nested inside already-decoded content (one level deep).
  const nested = [];
  for (const finding of findings) {
    if (!finding.decoded && finding.text && finding.kind !== 'base64') {
      for (const blob of findBase64(finding.text, finding.start, { origin: `${finding.kind} > base64` })) {
        // The inner offsets are not meaningful; keep the outer finding's range.
        nested.push({ ...blob, start: finding.start, end: finding.end, nested: true });
      }
    }
  }
  findings.push(...nested);

  // Deduplicate identical findings produced by overlapping passes.
  const unique = [];
  const seen = new Set();
  for (const finding of findings) {
    const key = `${finding.kind}|${finding.start}|${finding.end}|${finding.text?.slice(0, 80)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({ layer: 'L1', ...finding });
  }
  unique.sort((a, b) => a.start - b.start);

  const hiddenText = unique
    .filter((f) => f.text && f.kind !== 'zero-width' && f.kind !== 'bidi-control' && f.kind !== 'unicode-tag')
    .map((f) => f.text)
    .join('\n');

  // Score: saturating sum so many weak signals cannot alone reach certainty.
  let score = 0;
  for (const finding of unique) score += (finding.weight ?? 0) * (1 - score);

  return {
    layer: 'L1',
    score: Math.min(1, Number(score.toFixed(4))),
    findings: unique,
    spans: unique.map((f) => ({
      start: f.start,
      end: f.end,
      layer: 'L1',
      rule: f.kind,
      weight: f.weight ?? 0,
      text: f.text,
      preview: preview(f.text ?? '', 70),
    })),
    visibleText,
    hiddenText,
    stats: {
      isHTML,
      findingCount: unique.length,
      kinds: [...new Set(unique.map((f) => f.kind))],
      instructionShaped: unique.filter((f) => f.instruction).length,
    },
  };
}

export default extractHidden;
