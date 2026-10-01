/**
 * Tiny zero-dependency ANSI colour helper.
 *
 * Colour is disabled when any of the following hold, matching the de-facto
 * conventions so that `--json` output and CI logs stay byte-clean:
 *   - the NO_COLOR environment variable is set (https://no-color.org)
 *   - TERM is "dumb"
 *   - stdout is not a TTY (piping, redirecting, spawned from a test)
 *   - disable() was called explicitly (the CLI's --no-color / --json flags)
 */

const ESC = '\u001b';

const CODES = {
  reset: 0,
  bold: 1,
  dim: 2,
  italic: 3,
  underline: 4,
  red: 31,
  green: 32,
  yellow: 33,
  blue: 34,
  magenta: 35,
  cyan: 36,
  gray: 90,
};

function detectEnabled() {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== '') return false;
  if (process.env.TERM === 'dumb') return false;
  if (process.env.FORCE_COLOR !== undefined && process.env.FORCE_COLOR !== '0') return true;
  return Boolean(process.stdout && process.stdout.isTTY);
}

let enabled = detectEnabled();

export function disable() {
  enabled = false;
}

export function enable() {
  enabled = true;
}

export function isEnabled() {
  return enabled;
}

function wrap(name) {
  const code = CODES[name];
  return (text) => (enabled ? `${ESC}[${code}m${text}${ESC}[0m` : String(text));
}

export const bold = wrap('bold');
export const dim = wrap('dim');
export const italic = wrap('italic');
export const underline = wrap('underline');
export const red = wrap('red');
export const green = wrap('green');
export const yellow = wrap('yellow');
export const blue = wrap('blue');
export const magenta = wrap('magenta');
export const cyan = wrap('cyan');
export const gray = wrap('gray');

/** Colour a verdict string consistently everywhere it is printed. */
export function verdictColor(verdict) {
  if (verdict === 'injection') return red(bold(String(verdict).toUpperCase()));
  if (verdict === 'suspicious') return yellow(bold(String(verdict).toUpperCase()));
  return green(bold(String(verdict).toUpperCase()));
}

/** A short inverse-video badge, e.g. BLOCKED / ALLOWED. */
export function badge(text, kind = 'info') {
  if (!enabled) return `[${text}]`;
  const bg = kind === 'bad' ? 41 : kind === 'warn' ? 43 : 42;
  const fg = kind === 'warn' ? 30 : 97;
  return `${ESC}[${bg};${fg};1m ${text} ${ESC}[0m`;
}

// eslint-disable-next-line no-control-regex
const ANSI_RE = new RegExp(`${ESC}\[[0-9;]*m`, 'g');

/**
 * Visible width of a string once ANSI escapes are removed. Used by the demo's
 * side-by-side table so colour never breaks the column alignment.
 */
export function visibleLength(text) {
  return String(text).replace(ANSI_RE, '').length;
}

/** Strip ANSI escapes entirely. */
export function stripAnsi(text) {
  return String(text).replace(ANSI_RE, '');
}

/** Pad to `width` using visible (escape-free) length. */
export function padEnd(text, width) {
  const pad = Math.max(0, width - visibleLength(text));
  return `${text}${' '.repeat(pad)}`;
}
