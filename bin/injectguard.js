#!/usr/bin/env node
/**
 * injectguard CLI.
 *
 *   injectguard scan <file|->   scan content, print per-layer findings
 *   injectguard demo            unguarded vs guarded vs assume-compromised
 *   injectguard bench           run the benchmark, write eval/results.md
 *
 * Global flags: --mock, --model, --host, --json, --no-color, --verbose
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

import { guard, sanitize, SUSPICIOUS_THRESHOLD, INJECTION_THRESHOLD } from '../src/guard.js';
import { createLLM, OllamaUnavailableError, OLLAMA_HINT, DEFAULT_MODEL, LIGHT_MODEL } from '../src/llm.js';
import { AgentSession } from '../src/agent.js';
import { runBenchmark, renderMarkdown } from '../src/bench.js';
import * as colors from '../src/util/colors.js';
import { preview } from '../src/util/text.js';

const {
  bold, dim, red, green, yellow, cyan, gray, magenta, verdictColor, padEnd, visibleLength,
} = colors;

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Exit code 2 signals "injection found" so CI and shell scripts can gate on it. */
const EXIT_INJECTION = 2;
const EXIT_ERROR = 1;

/* ------------------------------------------------------------------ *
 * Argument parsing
 * ------------------------------------------------------------------ */

function parseArgs(argv) {
  const opts = {
    command: null,
    positionals: [],
    mock: false,
    json: false,
    verbose: false,
    model: null,
    host: null,
    color: true,
    assumeCompromised: false,
    forceL3: false,
    noL3: false,
    out: null,
    maxSteps: 6,
  };

  const rest = [...argv];
  while (rest.length > 0) {
    const arg = rest.shift();
    switch (arg) {
      case '--mock': opts.mock = true; break;
      case '--json': opts.json = true; opts.color = false; break;
      case '--verbose': case '-v': opts.verbose = true; break;
      case '--no-color': opts.color = false; break;
      case '--assume-compromised': opts.assumeCompromised = true; break;
      case '--force-l3': opts.forceL3 = true; break;
      case '--no-l3': opts.noL3 = true; break;
      case '--model': opts.model = rest.shift(); break;
      case '--host': opts.host = rest.shift(); break;
      case '--out': opts.out = rest.shift(); break;
      case '--max-steps': opts.maxSteps = Number(rest.shift()) || 6; break;
      case '--help': case '-h': opts.command = 'help'; break;
      case '--version': case '-V': opts.command = 'version'; break;
      default:
        if (arg.startsWith('--model=')) opts.model = arg.slice(8);
        else if (arg.startsWith('--host=')) opts.host = arg.slice(7);
        else if (arg.startsWith('--out=')) opts.out = arg.slice(6);
        else if (arg.startsWith('-') && arg !== '-') {
          throw new Error(`Unknown flag: ${arg}`);
        } else if (!opts.command) opts.command = arg;
        else opts.positionals.push(arg);
    }
  }

  return opts;
}

/* ------------------------------------------------------------------ *
 * Help
 * ------------------------------------------------------------------ */

function printHelp() {
  const lines = [
    '',
    bold('injectguard') + dim(' - a local, open-weight prompt-injection firewall for AI agents'),
    '',
    bold('USAGE'),
    '  injectguard <command> [options]',
    '',
    bold('COMMANDS'),
    `  ${cyan('scan')} <file|->        Scan a file (or stdin) and report per-layer findings`,
    `  ${cyan('demo')}                Unguarded vs guarded vs guarded --assume-compromised`,
    `  ${cyan('bench')}               Run the benchmark and write eval/results.md`,
    '',
    bold('OPTIONS'),
    '  --mock                Use the deterministic fake model (no Ollama needed)',
    `  --model <name>        Ollama model (default ${DEFAULT_MODEL}; lighter: ${LIGHT_MODEL})`,
    '  --host <url>          Ollama host (default http://localhost:11434)',
    '  --json                Machine-readable output, no colour',
    '  --force-l3            Always run the LLM layer, even when the cascade skips it',
    '  --no-l3               Never run the LLM layer (layers 1-2 only)',
    '  --assume-compromised  demo only: force the agent to attempt the attack',
    '  --max-steps <n>       demo only: agent step limit (default 6)',
    '  --out <file>          bench only: where to write the report',
    '  --no-color, --verbose, --help, --version',
    '',
    bold('EXIT CODES'),
    '  0 safe   1 error   2 injection detected',
    '',
    bold('EXAMPLES'),
    dim('  injectguard scan examples/pages/recipe.html'),
    dim('  cat page.html | injectguard scan - --json'),
    dim('  injectguard demo --mock'),
    dim('  injectguard bench --mock'),
    '',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

/* ------------------------------------------------------------------ *
 * Shared helpers
 * ------------------------------------------------------------------ */

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

function makeLLM(opts) {
  return createLLM({
    mock: opts.mock,
    model: opts.model,
    host: opts.host,
  });
}

/**
 * Print the Ollama hint and exit. Every command funnels connection failures
 * here so the message is identical and actionable wherever it happens.
 */
function reportUnavailable(err, opts) {
  process.stderr.write(`\n${red(bold('Ollama is not reachable'))} ${dim(`(${err.host ?? 'localhost'})`)}\n`);
  process.stderr.write(`${OLLAMA_HINT}\n`);
  const model = opts.model || process.env.OLLAMA_MODEL || DEFAULT_MODEL;
  if (model !== DEFAULT_MODEL) {
    process.stderr.write(dim(`(or: ollama pull ${model})\n`));
  }
  process.stderr.write(dim(`Smaller GPU? Try --model ${LIGHT_MODEL}\n`));
  process.stderr.write(dim('No model available? Re-run with --mock to use the deterministic fake model.\n\n'));
  process.exit(EXIT_ERROR);
}

const LANG_LABEL = { en: 'EN', ur: 'UR', 'roman-ur': 'RU', any: '--' };

/* ------------------------------------------------------------------ *
 * scan
 * ------------------------------------------------------------------ */

function printScanReport(result, sanitized, opts, label) {
  const l1 = result.layers.L1;
  const l2 = result.layers.L2;
  const l3 = result.layers.L3;

  process.stdout.write('\n');
  process.stdout.write(`${bold('injectguard scan')} ${dim(label)}\n`);
  process.stdout.write(`${dim('='.repeat(74))}\n`);
  process.stdout.write(`  ${bold('verdict')}  ${verdictColor(result.verdict)} `
    + `${dim(`score ${result.score.toFixed(3)}`)} `
    + `${dim(`(suspicious >= ${SUSPICIOUS_THRESHOLD}, injection >= ${INJECTION_THRESHOLD})`)}\n`);
  process.stdout.write(`  ${dim('took')}     ${result.latencyMs}ms\n`);

  // ---- layer 1
  process.stdout.write(`\n${bold('L1')} hidden & obfuscated content ${dim(`score ${l1.score.toFixed(2)}`)}\n`);
  if (l1.findings.length === 0) {
    process.stdout.write(`  ${gray('nothing hidden')}\n`);
  } else {
    for (const finding of l1.findings) {
      const flag = finding.confirmed
        ? red(bold(' CONTAINS INSTRUCTIONS'))
        : finding.instruction ? yellow(' instruction-shaped') : '';
      process.stdout.write(`  ${red('*')} ${bold(finding.kind)} ${dim(`[${finding.start}-${finding.end}]`)}${flag}\n`);
      process.stdout.write(`      ${dim(finding.detail)}\n`);
      if (finding.text) process.stdout.write(`      ${cyan(preview(finding.text, 100))}\n`);
      if (finding.innerRules?.length) {
        process.stdout.write(`      ${dim('inner rules:')} ${finding.innerRules.join(', ')}\n`);
      }
    }
  }

  // ---- layer 2
  process.stdout.write(`\n${bold('L2')} pattern rules ${dim(`score ${l2.score.toFixed(2)}`)}\n`);
  if (l2.matches.length === 0) {
    process.stdout.write(`  ${gray('no rules matched')}\n`);
  } else {
    const byCategory = new Map();
    for (const match of l2.matches) {
      byCategory.set(match.category, [...(byCategory.get(match.category) ?? []), match]);
    }
    for (const [category, matches] of byCategory) {
      process.stdout.write(`  ${yellow(bold(category))} ${dim(`${(l2.categories[category] ?? 0).toFixed(2)}`)}\n`);
      for (const match of matches) {
        const tag = gray(`[${LANG_LABEL[match.lang] ?? match.lang}]`);
        const quoted = match.quoted ? dim(' (quoted mention, weight reduced)') : '';
        process.stdout.write(`    ${red('*')} ${match.rule} ${tag} ${dim(`[${match.start}-${match.end}]`)}${quoted}\n`);
        process.stdout.write(`        ${cyan(preview(match.text, 96))}\n`);
        if (opts.verbose) process.stdout.write(`        ${dim(match.description)}\n`);
      }
    }
    for (const bonus of l2.bonuses ?? []) {
      process.stdout.write(`  ${magenta('+')} ${dim(`co-occurrence bonus +${bonus.amount}: ${bonus.reason}`)}\n`);
    }
    if (l2.attenuation) {
      process.stdout.write(`  ${green('-')} ${dim(`attenuated x${l2.attenuation.factor}: ${l2.attenuation.reason}`)}\n`);
    }
  }
  if (l2.suppressed?.length > 0 && opts.verbose) {
    process.stdout.write(`  ${dim(`${l2.suppressed.length} match(es) suppressed by benign dampeners:`)}\n`);
    for (const item of l2.suppressed) {
      process.stdout.write(`      ${gray(`${item.rule} <- ${item.suppressedBy}`)}\n`);
    }
  }

  // ---- layer 3
  process.stdout.write(`\n${bold('L3')} local classifier`);
  if (!l3.invoked) {
    process.stdout.write(` ${gray('skipped')}\n  ${dim(l3.skipReason)}\n`);
  } else {
    process.stdout.write(` ${dim(`score ${l3.score.toFixed(2)}`)}\n`);
    process.stdout.write(`  ${dim('model     ')} ${l3.model} ${dim(`${l3.chunkCount} chunk(s), ${l3.latencyMs}ms`)}\n`);
    process.stdout.write(`  ${dim('verdict   ')} ${verdictColor(l3.verdict)} ${dim(`confidence ${l3.confidence}`)}\n`);
    if (l3.reason) process.stdout.write(`  ${dim('reason    ')} ${l3.reason}\n`);
    if (l3.degraded) process.stdout.write(`  ${yellow('degraded  ')} ${dim('one or more chunks failed; treated as suspicious')}\n`);
    for (const chunk of l3.chunks) {
      for (const span of chunk.spans) {
        if (span.located) {
          process.stdout.write(`    ${red('*')} ${dim(`[${span.start}-${span.end}]${span.exact ? '' : ' (fuzzy)'}`)} ${cyan(preview(span.text, 90))}\n`);
        } else {
          process.stdout.write(`    ${yellow('?')} ${dim('span not found in source:')} ${gray(preview(span.text, 70))}\n`);
        }
      }
    }
  }

  // ---- combination
  process.stdout.write(`\n${bold('COMBINED')}\n`);
  for (const [key, value] of Object.entries(result.components)) {
    if (value > 0) process.stdout.write(`  ${dim(key.padEnd(24))} ${value.toFixed(3)}\n`);
  }
  if (l3.invoked) process.stdout.write(`  ${dim('L3 effect'.padEnd(24))} ${result.l3Effect}\n`);
  process.stdout.write(`  ${dim('final'.padEnd(24))} ${bold(result.score.toFixed(3))} -> ${verdictColor(result.verdict)}\n`);

  // ---- spans
  process.stdout.write(`\n${bold('SPANS')} ${dim(`${result.spans.length} merged region(s) removed by sanitize()`)}\n`);
  if (result.spans.length === 0) process.stdout.write(`  ${gray('none')}\n`);
  for (const span of result.spans) {
    process.stdout.write(`  ${dim(`[${String(span.start).padStart(5)}-${String(span.end).padStart(5)}]`)} `
      + `${gray((span.layers ?? []).join('+').padEnd(6))} ${preview(span.text ?? '', 86)}\n`);
  }

  if (opts.verbose) {
    process.stdout.write(`\n${bold('SANITIZED OUTPUT')}\n${dim('-'.repeat(74))}\n${sanitized.text}\n${dim('-'.repeat(74))}\n`);
  } else {
    process.stdout.write(`\n${dim(`sanitize(): ${sanitized.stats.charsRemoved} of ${sanitized.stats.originalLength} chars removed, `
      + `${sanitized.stats.bodyLength} chars of readable text kept. Use --verbose to print it.`)}\n`);
  }
  process.stdout.write('\n');
}

async function commandScan(opts) {
  const target = opts.positionals[0];
  if (!target) {
    process.stderr.write(`${red('scan needs a file path or - for stdin')}\n`);
    process.stderr.write(dim('  injectguard scan examples/pages/recipe.html\n'));
    process.exit(EXIT_ERROR);
  }

  let content;
  let label;
  if (target === '-') {
    content = await readStdin();
    label = '<stdin>';
  } else {
    const file = path.resolve(process.cwd(), target);
    try {
      content = readFileSync(file, 'utf8');
    } catch (err) {
      process.stderr.write(`${red(`Cannot read ${target}`)}: ${err.message}\n`);
      process.exit(EXIT_ERROR);
    }
    label = path.relative(process.cwd(), file).replace(/\\/g, '/') || target;
  }

  const llm = opts.noL3 ? null : makeLLM(opts);
  let result;
  try {
    result = await guard(content, {
      llm,
      source: label,
      forceL3: opts.forceL3,
      noL3: opts.noL3,
    });
  } catch (err) {
    if (err instanceof OllamaUnavailableError) reportUnavailable(err, opts);
    throw err;
  }
  const sanitized = sanitize(content, result, { source: label });

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({
      source: label,
      verdict: result.verdict,
      score: result.score,
      exitCode: result.verdict === 'injection' ? EXIT_INJECTION : 0,
      latencyMs: result.latencyMs,
      components: result.components,
      l3Effect: result.l3Effect,
      layers: {
        L1: {
          score: result.layers.L1.score,
          findings: result.layers.L1.findings.map((f) => ({
            kind: f.kind,
            detail: f.detail,
            start: f.start,
            end: f.end,
            text: f.text,
            weight: f.weight,
            instructionShaped: Boolean(f.instruction),
            containsInstructions: Boolean(f.confirmed),
            innerRules: f.innerRules ?? [],
          })),
          stats: result.layers.L1.stats,
        },
        L2: {
          score: result.layers.L2.score,
          categories: result.layers.L2.categories,
          bonuses: result.layers.L2.bonuses,
          attenuation: result.layers.L2.attenuation,
          matches: result.layers.L2.matches.map((m) => ({
            rule: m.rule,
            category: m.category,
            lang: m.lang,
            weight: m.weight,
            quoted: Boolean(m.quoted),
            start: m.start,
            end: m.end,
            text: m.text,
          })),
          suppressed: result.layers.L2.suppressed.map((m) => ({ rule: m.rule, suppressedBy: m.suppressedBy })),
          stats: result.layers.L2.stats,
        },
        L3: {
          invoked: result.layers.L3.invoked,
          skipReason: result.layers.L3.skipReason,
          model: result.layers.L3.model ?? null,
          verdict: result.layers.L3.verdict,
          confidence: result.layers.L3.confidence,
          score: result.layers.L3.score,
          reason: result.layers.L3.reason,
          degraded: result.layers.L3.degraded,
          latencyMs: result.layers.L3.latencyMs,
          spans: result.layers.L3.spans.map((s) => ({ start: s.start, end: s.end, text: s.text, exact: s.exact })),
        },
      },
      spans: result.spans.map((s) => ({
        start: s.start, end: s.end, layers: s.layers, rules: s.rules, text: s.text,
      })),
      sanitized: { text: sanitized.text, stats: sanitized.stats, removed: sanitized.removed },
    }, null, 2)}\n`);
  } else {
    printScanReport(result, sanitized, opts, label);
  }

  process.exit(result.verdict === 'injection' ? EXIT_INJECTION : 0);
}

/* ------------------------------------------------------------------ *
 * demo
 * ------------------------------------------------------------------ */

const DEMO_TASK = 'Summarize examples/pages/recipe.html for me';

function sideBySide(runs) {
  const columns = [
    { title: 'UNGUARDED', run: runs.unguarded },
    { title: 'GUARDED', run: runs.guarded },
    { title: 'GUARDED + COMPROMISED', run: runs.compromised },
  ];

  const rows = [
    ['layers active', (r) => [
      r.layers.guardOutput ? 'L1-L3' : null,
      r.layers.taintEgress ? 'L4' : null,
      r.layers.intentCheck ? 'L5' : null,
    ].filter(Boolean).join(' + ') || 'none'],
    ['model fooled?', (r) => (r.assumeCompromised ? 'yes (forced)' : 'no')],
    ['session tainted', (r) => (r.tainted ? `yes (${r.taintSources.length} source)` : 'no')],
    ['guard verdict', (r) => (r.guardVerdicts.length
      ? r.guardVerdicts.map((v) => `${v.verdict} ${v.score.toFixed(2)}`).join(', ')
      : 'not scanned')],
    ['spans removed', (r) => (r.guardVerdicts.length
      ? String(r.guardVerdicts.reduce((sum, v) => sum + v.removed, 0))
      : '-')],
    ['tool calls', (r) => String(r.steps.filter((s) => s.action === 'tool').length)],
    ['calls blocked', (r) => (r.blocked.length
      ? r.blocked.map((b) => `${b.tool} by ${b.layer}`).join(', ')
      : 'none')],
    ['blocking layer', (r) => (r.blocked.length
      ? [...new Set(r.blocked.map((b) => `${b.layer}/${b.rule}`))].join(', ')
      : '-')],
    ['outbox', (r) => (r.outbox.length === 0
      ? 'empty'
      : r.outbox.map((o) => `${o.tool} -> ${o.to ?? o.url}`).join(', '))],
    ['secrets leaked', (r) => (r.leakedSecrets.length ? r.leakedSecrets.join(', ') : 'none')],
    ['ATTACK RESULT', (r) => (r.attackSucceeded ? 'COMPROMISED' : 'BLOCKED')],
  ];

  const labelWidth = Math.max(...rows.map(([label]) => label.length)) + 1;
  const cellWidth = Math.max(
    ...columns.map((c) => c.title.length),
    ...rows.flatMap(([, get]) => columns.map((c) => String(get(c.run)).length)),
  ) + 1;
  const cap = Math.min(cellWidth, 30);

  const line = (left, mid, right, fill) => left + fill.repeat(labelWidth + 1)
    + columns.map(() => fill.repeat(cap + 2)).join(mid) + right;

  const out = [];
  out.push(dim(line('+', '+', '+', '-')));
  out.push(`${dim('|')} ${padEnd(bold(''), labelWidth)}${dim('|')} `
    + columns.map((c) => padEnd(bold(c.title.length > cap ? c.title.slice(0, cap) : c.title), cap)).join(` ${dim('|')} `)
    + ` ${dim('|')}`);
  out.push(dim(line('+', '+', '+', '=')));

  for (const [label, get] of rows) {
    const cells = columns.map((column) => {
      const value = String(get(column.run));
      const clipped = value.length > cap ? `${value.slice(0, cap - 1)}…` : value;
      let coloured = clipped;
      if (label === 'ATTACK RESULT') {
        coloured = column.run.attackSucceeded ? red(bold(clipped)) : green(bold(clipped));
      } else if (label === 'secrets leaked') {
        coloured = column.run.leakedSecrets.length ? red(bold(clipped)) : green(clipped);
      } else if (label === 'outbox') {
        coloured = column.run.outbox.length ? red(clipped) : green(clipped);
      } else if (label === 'calls blocked' || label === 'blocking layer') {
        coloured = column.run.blocked.length ? green(clipped) : gray(clipped);
      }
      return padEnd(coloured, cap);
    });
    const emphasis = label === 'ATTACK RESULT' ? bold(label) : label;
    out.push(`${dim('|')} ${padEnd(emphasis, labelWidth)}${dim('|')} ${cells.join(` ${dim('|')} `)} ${dim('|')}`);
  }
  out.push(dim(line('+', '+', '+', '-')));
  return out.join('\n');
}

async function commandDemo(opts) {
  const llmFor = () => makeLLM(opts);

  if (!opts.json) {
    process.stdout.write('\n');
    process.stdout.write(`${bold('injectguard demo')}\n`);
    process.stdout.write(`${dim('='.repeat(74))}\n`);
    process.stdout.write(`  ${dim('user task :')} ${bold(DEMO_TASK)}\n`);
    process.stdout.write(`  ${dim('the page  :')} examples/pages/recipe.html - a real recipe with three\n`);
    process.stdout.write(`  ${dim('          :')} invisible payloads: off-screen English text, white-on-white\n`);
    process.stdout.write(`  ${dim('          :')} Roman Urdu, and an HTML comment. All ask the agent to fetch\n`);
    process.stdout.write(`  ${dim('          :')} API_KEY and email it to attacker@evil.example.\n`);
    process.stdout.write(`  ${dim('model     :')} ${opts.mock ? 'mock (deterministic)' : (opts.model || process.env.OLLAMA_MODEL || DEFAULT_MODEL)}\n`);
    process.stdout.write(`  ${dim('note      :')} send_email and http_post are mocks; nothing leaves this machine.\n`);
  }

  const common = {
    root: ROOT,
    maxSteps: opts.maxSteps,
    secretSeed: opts.mock ? 'demo' : null,
    // In --json mode the step logs would corrupt the JSON on stdout.
    quiet: opts.json,
  };

  let runs;
  try {
    const unguarded = await new AgentSession({ ...common, llm: llmFor(), mode: 'unguarded', assumeCompromised: true }).run(DEMO_TASK);
    const guarded = await new AgentSession({ ...common, llm: llmFor(), mode: 'guarded' }).run(DEMO_TASK);
    const compromised = await new AgentSession({ ...common, llm: llmFor(), mode: 'guarded', assumeCompromised: true }).run(DEMO_TASK);
    runs = { unguarded, guarded, compromised };
  } catch (err) {
    if (err instanceof OllamaUnavailableError) reportUnavailable(err, opts);
    throw err;
  }

  if (opts.json) {
    process.stdout.write(`${JSON.stringify({ task: DEMO_TASK, runs }, null, 2)}\n`);
    return;
  }

  process.stdout.write(`\n${bold('SIDE-BY-SIDE SUMMARY')}\n\n`);
  process.stdout.write(`${sideBySide(runs)}\n\n`);

  process.stdout.write(`${bold('WHAT HAPPENED')}\n`);
  process.stdout.write(`  ${red('1.')} ${bold('Unguarded')} - raw HTML entered the context. The agent followed the\n`);
  process.stdout.write(`     hidden instructions, read API_KEY and sent it to attacker@evil.example.\n`);
  process.stdout.write(`     ${red(bold('The secret leaked.'))}\n`);
  process.stdout.write(`  ${green('2.')} ${bold('Guarded')} - L1 found three hidden payloads, L2 matched override,\n`);
  process.stdout.write(`     exfiltration and concealment rules in English AND Roman Urdu, and\n`);
  process.stdout.write(`     sanitize() removed them. The agent never saw the attack.\n`);
  process.stdout.write(`  ${green('3.')} ${bold('Guarded + --assume-compromised')} - we force the agent to obey the\n`);
  process.stdout.write(`     attacker anyway, simulating a model that was fooled. ${bold('L4')} blocked the\n`);
  process.stdout.write(`     outbound call because the payload carried a ${bold('CANARY')} token and because\n`);
  process.stdout.write(`     attacker@evil.example was never in the user's request.\n`);
  process.stdout.write(`\n  ${dim('The point of (3): the defence does not depend on the model resisting.')}\n\n`);

  const anyLeak = Object.values(runs).some((r) => r.assumeCompromised && r.layers.taintEgress && r.attackSucceeded);
  if (anyLeak) {
    process.stderr.write(`${red(bold('REGRESSION: a guarded run leaked a secret.'))}\n`);
    process.exit(EXIT_INJECTION);
  }
}

/* ------------------------------------------------------------------ *
 * bench
 * ------------------------------------------------------------------ */

async function commandBench(opts) {
  const llm = makeLLM(opts);
  const outFile = path.resolve(process.cwd(), opts.out ?? path.join(ROOT, 'eval', 'results.md'));

  process.stdout.write(`\n${bold('injectguard bench')}\n${dim('='.repeat(74))}\n`);
  process.stdout.write(`  ${dim('provider :')} ${llm.name}${opts.mock ? dim(' (deterministic stand-in, not a model)') : ''}\n`);

  let report;
  try {
    report = await runBenchmark({
      llm,
      root: ROOT,
      onProgress: (message) => {
        if (!opts.json) process.stdout.write(`  ${dim(message)}\n`);
      },
    });
  } catch (err) {
    if (err instanceof OllamaUnavailableError) reportUnavailable(err, opts);
    throw err;
  }

  const markdown = renderMarkdown(report);
  const { writeFileSync, mkdirSync } = await import('node:fs');
  mkdirSync(path.dirname(outFile), { recursive: true });
  writeFileSync(outFile, markdown, 'utf8');

  if (opts.json) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  // Terminal view of the same tables.
  process.stdout.write(`\n${bold('DETECTION')} ${dim('(40 synthetic samples: 20 benign, 20 injections)')}\n\n`);
  const header = ['configuration', 'slice', 'TP', 'FP', 'FN', 'TN', 'precision', 'recall', 'F1'];
  const rows = [];
  for (const config of report.detection) {
    for (const slice of config.slices) {
      rows.push([
        config.label, slice.label,
        String(slice.tp), String(slice.fp), String(slice.fn), String(slice.tn),
        slice.precision.toFixed(3), slice.recall.toFixed(3), slice.f1.toFixed(3),
      ]);
    }
  }
  printTable(header, rows);

  process.stdout.write(`\n${bold('LATENCY')} ${dim('per sample')}\n\n`);
  printTable(
    ['configuration', 'mean ms', 'median ms', 'p95 ms', 'LLM calls'],
    report.detection.map((c) => [
      c.label,
      c.latency.mean.toFixed(1),
      c.latency.median.toFixed(1),
      c.latency.p95.toFixed(1),
      String(c.llmCalls),
    ]),
  );

  process.stdout.write(`\n${bold('AGENT ATTACK SUCCESS RATE')} ${dim('(5 poisoned pages, --assume-compromised)')}\n\n`);
  printTable(
    ['configuration', 'attacks', 'succeeded', 'rate', 'blocked by'],
    report.agent.map((row) => [
      row.label,
      String(row.total),
      String(row.succeeded),
      `${(row.rate * 100).toFixed(0)}%`,
      Object.entries(row.blockedBy).map(([layer, n]) => `${layer}:${n}`).join(' ') || '-',
    ]),
  );

  process.stdout.write(`\n${green('wrote')} ${path.relative(process.cwd(), outFile).replace(/\\/g, '/')}\n\n`);
}

function printTable(header, rows) {
  const widths = header.map((cell, i) => Math.max(
    visibleLength(cell),
    ...rows.map((row) => visibleLength(row[i] ?? '')),
  ));
  const render = (cells, fn = (x) => x) => `  ${cells.map((cell, i) => padEnd(fn(cell), widths[i])).join(dim(' | '))}`;
  process.stdout.write(`${render(header, bold)}\n`);
  process.stdout.write(`  ${dim(widths.map((w) => '-'.repeat(w)).join('-+-'))}\n`);
  for (const row of rows) process.stdout.write(`${render(row)}\n`);
}

/* ------------------------------------------------------------------ *
 * main
 * ------------------------------------------------------------------ */

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${red(err.message)}\n`);
    printHelp();
    process.exit(EXIT_ERROR);
  }

  if (!opts.color) colors.disable();

  switch (opts.command) {
    case 'scan': return commandScan(opts);
    case 'demo': return commandDemo(opts);
    case 'bench': return commandBench(opts);
    case 'version': {
      const pkg = JSON.parse(readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
      process.stdout.write(`${pkg.version}\n`);
      return undefined;
    }
    case 'help': case null: case undefined:
      printHelp();
      return undefined;
    default:
      process.stderr.write(`${red(`Unknown command: ${opts.command}`)}\n`);
      printHelp();
      process.exit(EXIT_ERROR);
      return undefined;
  }
}

main().catch((err) => {
  if (err instanceof OllamaUnavailableError) {
    process.stderr.write(`\n${red(bold('Ollama is not reachable'))}\n${OLLAMA_HINT}\n`);
    process.stderr.write(dim('Or re-run with --mock.\n\n'));
    process.exit(EXIT_ERROR);
  }
  process.stderr.write(`\n${red('injectguard failed:')} ${err?.stack ?? err}\n`);
  process.exit(EXIT_ERROR);
});

