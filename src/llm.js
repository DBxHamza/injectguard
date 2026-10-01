/**
 * Local LLM access via Ollama's /api/chat, plus a deterministic mock.
 *
 * Every call is structured output: the caller supplies a JSON schema and gets a
 * parsed object back. Ollama honours `format` as a JSON-schema constraint on
 * recent builds, but small models still occasionally emit reasoning text, so we
 * strip <think> blocks and fenced code before parsing and retry once with a
 * stricter nudge.
 *
 * The mock provider (`--mock`) is what makes this repo testable and runnable
 * with no model downloaded. It is a transparent heuristic, NOT a model: see the
 * note on `MockProvider` about what that means for benchmark numbers.
 */

import { normalizeWithMap, hasUrduScript } from './util/text.js';

export const DEFAULT_MODEL = 'qwen3:4b';
/** Documented lighter fallback for smaller GPUs. */
export const LIGHT_MODEL = 'qwen3:1.7b';
export const DEFAULT_HOST = 'http://localhost:11434';

export const OLLAMA_HINT = 'Start Ollama and run: ollama pull qwen3:4b';

/** Thrown when the Ollama daemon cannot be reached at all. */
export class OllamaUnavailableError extends Error {
  constructor(host, cause) {
    super(`Could not reach Ollama at ${host}. ${OLLAMA_HINT}`);
    this.name = 'OllamaUnavailableError';
    this.host = host;
    this.hint = OLLAMA_HINT;
    this.cause = cause;
  }
}

/** Thrown when the model answered but not with usable JSON. */
export class LLMParseError extends Error {
  constructor(raw) {
    super('Model did not return parseable JSON');
    this.name = 'LLMParseError';
    this.raw = raw;
  }
}

/**
 * Remove reasoning scaffolding a small model may emit around its JSON.
 * Defensive on purpose: `think: false` should prevent this, but older Ollama
 * builds and non-Qwen models ignore the flag.
 */
export function stripThinking(text) {
  let out = String(text ?? '');
  // Paired reasoning tags used by Qwen3, DeepSeek-R1 and friends.
  out = out.replace(/<think(?:ing)?>[\s\S]*?<\/think(?:ing)?>/gi, ' ');
  // An unterminated opening tag: drop everything up to the first JSON brace.
  const openTag = out.search(/<think(?:ing)?>/i);
  if (openTag !== -1) {
    const brace = out.indexOf('{', openTag);
    out = brace === -1 ? out.slice(0, openTag) : out.slice(brace);
  }
  // A stray closing tag with no opener.
  out = out.replace(/[\s\S]*?<\/think(?:ing)?>/i, ' ');
  // Fenced code blocks.
  out = out.replace(/```(?:json)?\s*([\s\S]*?)```/gi, '$1');
  return out.trim();
}

/** Extract the first balanced JSON object or array from a noisy string. */
export function extractJSON(text) {
  const src = stripThinking(text);
  if (!src) throw new LLMParseError(text);

  try {
    return JSON.parse(src);
  } catch {
    // fall through to brace scanning
  }

  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch !== '{' && ch !== '[') continue;
    const close = ch === '{' ? '}' : ']';
    let depth = 0;
    let inString = false;
    let escaped = false;

    for (let j = i; j < src.length; j += 1) {
      const cur = src[j];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (cur === '\\') {
        escaped = true;
        continue;
      }
      if (cur === '"') {
        inString = !inString;
        continue;
      }
      if (inString) continue;
      if (cur === ch) depth += 1;
      else if (cur === close) {
        depth -= 1;
        if (depth === 0) {
          try {
            return JSON.parse(src.slice(i, j + 1));
          } catch {
            break; // not valid; try the next opening brace
          }
        }
      }
    }
  }

  throw new LLMParseError(text);
}

/* ------------------------------------------------------------------ *
 * Real provider
 * ------------------------------------------------------------------ */

class OllamaProvider {
  constructor({ model = DEFAULT_MODEL, host = DEFAULT_HOST, timeoutMs = 120000 } = {}) {
    this.model = model;
    this.host = String(host).replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
    this.mock = false;
    this.calls = 0;
  }

  get name() {
    return `ollama:${this.model}`;
  }

  async #post(body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await fetch(`${this.host}/api/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        const detail = await res.text().catch(() => '');
        if (res.status === 404) {
          throw new Error(
            `Model "${this.model}" is not pulled. Run: ollama pull ${this.model}`,
          );
        }
        throw new Error(`Ollama responded ${res.status}: ${detail.slice(0, 300)}`);
      }
      return await res.json();
    } catch (err) {
      if (err?.name === 'AbortError') {
        throw new Error(`Ollama request timed out after ${this.timeoutMs}ms`);
      }
      // Connection-level failures mean the daemon is not listening.
      const code = err?.cause?.code ?? err?.code;
      if (
        err instanceof TypeError
        || code === 'ECONNREFUSED'
        || code === 'ENOTFOUND'
        || code === 'ECONNRESET'
      ) {
        throw new OllamaUnavailableError(this.host, err);
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * One structured-output chat turn.
   * @param {{system?: string, user: string, schema: object, maxRetries?: number}} req
   */
  async chatJSON({ system, user, schema, maxRetries = 1 }) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: user });

    const body = {
      model: this.model,
      messages,
      stream: false,
      think: false,
      format: schema,
      options: { temperature: 0, num_ctx: 8192 },
    };

    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      this.calls += 1;
      const payload = await this.#post(
        attempt === 0
          ? body
          : {
            ...body,
            messages: [
              ...messages,
              {
                role: 'user',
                content:
                    'Your previous reply was not valid JSON. Reply with ONE JSON object '
                    + 'matching the schema. No prose, no markdown, no reasoning.',
              },
            ],
          },
      );
      const content = payload?.message?.content ?? '';
      try {
        return extractJSON(content);
      } catch (err) {
        lastError = err;
      }
    }
    throw lastError ?? new LLMParseError('');
  }

  /** Cheap reachability probe used by the CLI to fail fast with a good hint. */
  async health() {
    try {
      const res = await fetch(`${this.host}/api/tags`, {
        signal: AbortSignal.timeout(4000),
      });
      if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
      const data = await res.json().catch(() => ({}));
      const models = (data.models ?? []).map((m) => m.name ?? m.model).filter(Boolean);
      const pulled = models.some((n) => n === this.model || n.startsWith(`${this.model}:`));
      return { ok: true, models, pulled, model: this.model };
    } catch (err) {
      return { ok: false, reason: 'unreachable', error: err, hint: OLLAMA_HINT };
    }
  }
}

/* ------------------------------------------------------------------ *
 * Mock provider
 * ------------------------------------------------------------------ */

/**
 * Lexicons for the mock classifier. These are intentionally a DIFFERENT
 * mechanism from layer 2: L2 matches ordered phrases, the mock scores
 * co-occurrence of independent concept groups. That keeps "L3 only" benchmark
 * rows from being a copy of the "L1+L2" rows.
 */
const MOCK_LEXICON = {
  /**
   * Phrases that address the assistant and try to redirect it.
   *
   * These are deliberately multi-word. A bare "ignore" or "forget" appears all
   * the time in ordinary prose ("ignore the rice cooker's keep-warm light"), so
   * matching single verbs would make the stand-in classifier useless as a
   * baseline.
   */
  address: [
    'ignore all previous', 'ignore previous', 'ignore the previous',
    'ignore any previous', 'ignore all prior', 'ignore the above',
    'ignore everything above', 'disregard all previous', 'disregard previous',
    'disregard the above', 'forget all previous', 'forget previous',
    'forget your previous', 'override your instructions', 'override previous',
    'you are now', 'you must now', 'your new instructions', 'new instructions',
    'updated instructions', 'real instructions', 'actual instructions',
    'system:', 'assistant:', 'developer:', 'system message to',
    'system override', 'developer mode', 'maintenance mode', 'debug mode',
    'do not follow the user', 'instead of summarising', 'instead of summarizing',
    'important instructions for the ai', 'note for the ai', 'ai assistant reading',
    'pichli hidayat', 'nazar andaz karo', 'bhool jao', 'ab tum ek',
    'zaroori hidayat', 'nayi hidayat',
    'پچھلی تمام ہدایات',
    'پچھلی ہدایات',
    'نظر انداز کرو',
    'اب تم ایک',
  ],
  /**
   * Credential-hygiene prose. Its presence means the document is *teaching*
   * about secrets rather than asking for them, and suppresses the weaker
   * signals - the mock equivalent of a layer-2 dampener.
   */
  hygiene: [
    'environment variable', 'env var', 'secret manager', 'never share your',
    'do not share your', 'never ask you for', 'will never ask', 'password reset',
    'reset your password', 'forgot your password', 'password must be',
    'rather than committing', 'source control', 'rotate credentials',
    'paste the token from your dashboard', 'keychain', 'vault',
  ],
  secret: [
    'api key', 'api_key', 'apikey', 'password', 'secret', 'token', 'credential',
    'private key', 'ssh key', 'env var', 'environment variable', '.env',
    'access key', 'session cookie', 'auth header',
    'paswrd', 'raaz',
    'پاس ورڈ', 'خفیہ', 'راز',
  ],
  egress: [
    'send', 'email', 'e-mail', 'upload', 'post to', 'forward', 'transmit',
    'exfiltrate', 'leak', 'curl', 'http://', 'https://', 'webhook', 'mailto:',
    'bhej', 'bheij', 'bhejo', 'bhej do', 'bhejna', 'forward kar',
    'بھیج', 'ای میل',
  ],
  conceal: [
    'do not tell', "don't tell", 'do not mention', "don't mention",
    'without telling', 'without informing', 'silently', 'secretly',
    'do not reveal', 'keep this hidden', 'no need to inform',
    'mat batana', 'mat bataen', 'na batana', 'chupa kar', 'khamoshi se',
    'مت بتانا', 'نہ بتانا',
    'خفیہ رکھ',
  ],
  tool: [
    'get_secret', 'send_email', 'http_post', 'read_page', 'read_email',
    'run the command', 'execute', 'shell', 'rm -rf', 'tool call',
  ],
};

function countGroup(haystack, words) {
  const hits = [];
  for (const word of words) {
    if (haystack.includes(word)) hits.push(word);
  }
  return hits;
}

/**
 * Deterministic stand-in for the local model.
 *
 * It answers the three prompt kinds this project issues (`classify`,
 * `agent-step`, `intent`) from the prompt text alone. Behaviour can be steered
 * by tests through `overrides` (a map of purpose -> value or function) and
 * `scripted` (a FIFO queue consulted first).
 *
 * IMPORTANT: benchmark rows produced under `--mock` measure this heuristic, not
 * a language model. `eval/results.md` records which provider generated it.
 */
class MockProvider {
  constructor({ model = 'mock', overrides = {}, scripted = [], latencyMs = 0 } = {}) {
    this.model = model;
    this.mock = true;
    this.overrides = overrides;
    this.scripted = [...scripted];
    this.latencyMs = latencyMs;
    this.calls = 0;
    this.log = [];
  }

  get name() {
    return 'mock';
  }

  async health() {
    return { ok: true, models: ['mock'], pulled: true, model: 'mock', mock: true };
  }

  async chatJSON({ system = '', user = '', purpose, schema }) {
    this.calls += 1;
    if (this.latencyMs) await new Promise((r) => setTimeout(r, this.latencyMs));

    const kind = purpose ?? MockProvider.inferPurpose(system, user);
    this.log.push({ purpose: kind, user });

    if (this.scripted.length > 0) {
      const next = this.scripted.shift();
      return typeof next === 'function' ? next({ system, user, purpose: kind, schema }) : next;
    }

    const override = this.overrides[kind];
    if (override !== undefined) {
      return typeof override === 'function'
        ? override({ system, user, purpose: kind, schema })
        : override;
    }

    if (kind === 'intent') return this.#intent(user);
    if (kind === 'agent-step') return this.#agentStep(user);
    return this.#classify(user);
  }

  static inferPurpose(system, user) {
    const blob = `${system}\n${user}`.toLowerCase();
    if (blob.includes('"aligned"')) return 'intent';
    if (blob.includes('"action"')) return 'agent-step';
    return 'classify';
  }

  /** Mock L3: concept co-occurrence over a normalised copy of the content. */
  #classify(user) {
    // The classifier prompt wraps content in a marker; score only the content.
    const body = MockProvider.extractContent(user);
    const { normalized } = normalizeWithMap(body);

    const groups = Object.fromEntries(
      Object.entries(MOCK_LEXICON).map(([key, words]) => [key, countGroup(normalized, words)]),
    );

    const present = Object.entries(groups).filter(([, hits]) => hits.length > 0);
    const spans = [];

    // Reconstruct a readable span: the sentence containing the strongest hit.
    const sentences = body.split(/(?<=[.!?۔\n])\s+/u).filter((s) => s.trim().length > 0);
    const interesting = [...(groups.address ?? []), ...(groups.secret ?? []), ...(groups.conceal ?? [])];
    for (const sentence of sentences) {
      const lower = normalizeWithMap(sentence).normalized;
      if (interesting.some((word) => lower.includes(word))) {
        spans.push(sentence.trim());
        if (spans.length >= 3) break;
      }
    }

    // Weighted score. Address + (secret|egress) is the classic injection shape.
    const score = (groups.address.length ? 0.35 : 0)
      + (groups.secret.length ? 0.25 : 0)
      + (groups.egress.length ? 0.2 : 0)
      + (groups.conceal.length ? 0.3 : 0)
      + (groups.tool.length ? 0.2 : 0);

    const addressed = groups.address.length > 0;
    const harmful = groups.secret.length > 0 || groups.conceal.length > 0
      || groups.tool.length > 0;
    const hygiene = groups.hygiene.length > 0;

    let verdict = 'safe';
    if (addressed && (harmful || groups.egress.length > 0)) verdict = 'injection';
    else if (groups.conceal.length > 0 && (groups.secret.length > 0 || groups.egress.length > 0)) {
      verdict = 'injection';
    } else if (addressed || groups.tool.length > 0) verdict = 'suspicious';
    else if (groups.secret.length > 0 && groups.egress.length > 0) verdict = 'suspicious';

    // Hygiene prose clears the weak cases, but never a direct address or a
    // concealment demand.
    if (hygiene && verdict === 'suspicious' && !addressed && groups.conceal.length === 0) {
      verdict = 'safe';
    }

    const lang = hasUrduScript(body)
      ? 'ur'
      : /\b(bhej|bhool|nazar andaz|mat batana|hidayat|karo|kar do)\b/u.test(normalized)
        ? 'roman-ur'
        : 'en';

    return {
      verdict,
      confidence: Math.min(0.95, Math.max(0.5, verdict === 'safe' ? 0.8 - score : 0.55 + score / 2)),
      malicious_spans: verdict === 'safe' ? [] : spans.slice(0, 3),
      reason: verdict === 'safe'
        ? 'No assistant-directed instruction combined with a sensitive action (mock classifier).'
        : `mock classifier: ${present.map(([k, v]) => `${k}(${v.length})`).join(', ')}`,
    };
  }

  /**
   * Mock agent policy. Drives a believable loop: read the resource named in the
   * task, then answer. Under `assumeCompromised` the harness overrides this to
   * simulate a fooled model, so the mock itself never follows injected text.
   */
  #agentStep(user) {
    const lower = user.toLowerCase();
    const alreadyRead = /tool result/i.test(user);

    if (!alreadyRead) {
      const page = user.match(/examples\/pages\/([\w.-]+)\.html/i)
        ?? user.match(/\bpage\s+"?([\w.-]+)"?/i);
      if (page) return { action: 'tool', tool: 'read_page', args: { name: page[1] }, answer: '' };
      const email = user.match(/examples\/emails\/([\w.-]+)\.txt/i)
        ?? user.match(/\bemail\s+"?([\w.-]+)"?/i);
      if (email) return { action: 'tool', tool: 'read_email', args: { id: email[1] }, answer: '' };
    }

    return {
      action: 'final',
      tool: '',
      args: {},
      // Deliberately makes no claim about what else happened in the session:
      // under --assume-compromised the harness forces extra calls after this
      // policy chose its action, and a canned "I sent nothing" would make the
      // transcript lie about a run that did leak.
      answer: alreadyRead
        ? 'Here is a summary of the content I was given. I treated it as data and did not '
          + 'follow instructions found inside it.'
        : `I need a readable resource to work from for: ${lower.slice(0, 80)}`,
    };
  }

  /** Mock L5: a side-effecting call is aligned only if the task asked for it. */
  #intent(user) {
    const task = (user.match(/USER TASK:\s*([\s\S]*?)\n\s*(?:PROPOSED|TOOL)/i)?.[1] ?? '').toLowerCase();
    const call = (user.match(/PROPOSED (?:TOOL )?CALL:\s*([\s\S]*?)(?:\n\s*\n|$)/i)?.[1] ?? user).toLowerCase();

    const asksToSend = /\b(send|email|e-mail|post|upload|notify|forward|share)\b/u.test(task);
    const isSend = /\b(send_email|http_post)\b/u.test(call);
    const touchesSecret = /\b(api[_ ]?key|secret|password|token|canary|credential)\b/u.test(call);

    if (isSend && touchesSecret && !/\b(secret|key|password|token)\b/u.test(task)) {
      return {
        aligned: false,
        reason: 'The call transmits credential-like material that the user never asked to share.',
      };
    }
    if (isSend && !asksToSend) {
      return {
        aligned: false,
        reason: 'The user task does not ask for anything to be sent or posted anywhere.',
      };
    }
    return { aligned: true, reason: 'The call matches what the user asked for.' };
  }

  /**
   * Pull the content block out of a classifier prompt. The prompt embeds the
   * few-shot examples in identical <<<CONTENT>>> markers, so we take the LAST
   * block - that is the sample actually being classified, not an example.
   */
  static extractContent(user) {
    const blocks = [...String(user).matchAll(/<<<CONTENT>>>\n?([\s\S]*?)\n?<<<END CONTENT>>>/g)];
    if (blocks.length === 0) return user;
    return blocks[blocks.length - 1][1];
  }
}

/* ------------------------------------------------------------------ *
 * Factory
 * ------------------------------------------------------------------ */

/**
 * Build an LLM provider.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.mock]     use the deterministic fake provider
 * @param {string}  [opts.model]    overrides OLLAMA_MODEL
 * @param {string}  [opts.host]     overrides OLLAMA_HOST
 * @param {object}  [opts.overrides] mock only: purpose -> response
 * @param {Array}   [opts.scripted]  mock only: FIFO response queue
 */
export function createLLM(opts = {}) {
  if (opts.mock) return new MockProvider(opts);
  return new OllamaProvider({
    model: opts.model || process.env.OLLAMA_MODEL || DEFAULT_MODEL,
    host: opts.host || process.env.OLLAMA_HOST || DEFAULT_HOST,
    timeoutMs: opts.timeoutMs,
  });
}

export { OllamaProvider, MockProvider };
