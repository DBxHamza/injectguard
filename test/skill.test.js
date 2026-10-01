// SKILL.md validator: enforces the Agent Skills open standard rules from MUST 5.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SKILL_DIR = path.join(ROOT, 'skills', 'injection-guard');
const SKILL_MD = path.join(SKILL_DIR, 'SKILL.md');

/** Minimal front-matter parser (no YAML dependency). */
function parseFrontmatter(text) {
  const match = /^---\n([\s\S]*?)\n---\n([\s\S]*)$/.exec(text);
  if (!match) return { frontmatter: null, body: text };
  const frontmatter = {};
  for (const line of match[1].split('\n')) {
    const m = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(line);
    if (m) frontmatter[m[1]] = m[2].trim();
  }
  return { frontmatter, body: match[2], rawFrontmatter: match[1] };
}

const text = readFileSync(SKILL_MD, 'utf8');
const { frontmatter, body, rawFrontmatter } = parseFrontmatter(text);

test('SKILL.md exists and has YAML front matter', () => {
  assert.ok(existsSync(SKILL_MD));
  assert.ok(frontmatter, 'front matter must parse');
});

test('name matches the folder and the naming rules', () => {
  assert.equal(frontmatter.name, 'injection-guard');
  assert.equal(frontmatter.name, path.basename(SKILL_DIR));
  // lowercase letters, digits, hyphens; no leading/trailing/double hyphens; <=64
  assert.match(frontmatter.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.ok(frontmatter.name.length <= 64);
  assert.ok(!frontmatter.name.startsWith('-') && !frontmatter.name.endsWith('-'));
  assert.ok(!frontmatter.name.includes('--'));
});

test('description is present, within 1024 chars, and states WHAT and WHEN', () => {
  assert.ok(frontmatter.description, 'description required');
  assert.ok(frontmatter.description.length <= 1024, `description is ${frontmatter.description.length} chars`);
  assert.ok(frontmatter.description.length >= 40);
  const d = frontmatter.description.toLowerCase();
  // WHAT
  assert.ok(/(scan|detect|inject)/.test(d), 'description should say what it does');
  // WHEN - acting on fetched/untrusted content, before side-effecting actions
  assert.ok(/before/.test(d), 'description should say when (before ...)');
  assert.ok(/(web page|page|email|document|file|tool)/.test(d));
  assert.ok(/(send|side-effect|tool|command)/.test(d), 'description should mention acting/sending');
});

test('license is Apache-2.0', () => {
  assert.equal(frontmatter.license, 'Apache-2.0');
});

test('only spec fields are used in front matter', () => {
  const allowed = new Set([
    'name', 'description', 'license', 'version', 'compatibility',
    'allowed-tools', 'allowed_directories', 'metadata',
  ]);
  const used = rawFrontmatter.split('\n')
    .map((l) => /^([A-Za-z0-9_-]+):/.exec(l)?.[1])
    .filter(Boolean);
  for (const key of used) {
    assert.ok(allowed.has(key), `unexpected front-matter field: ${key}`);
  }
  // The three required-by-the-task fields must be present.
  for (const key of ['name', 'description', 'license']) {
    assert.ok(used.includes(key), `missing required field: ${key}`);
  }
});

test('body is under 300 lines', () => {
  const lines = body.split('\n').length;
  assert.ok(lines < 300, `body has ${lines} lines`);
});

test('body teaches the core behaviours', () => {
  const b = body.toLowerCase();
  assert.ok(b.includes('scan.mjs'), 'should reference scripts/scan.mjs');
  assert.ok(/sanitized/.test(b), 'should tell the agent to act on sanitized output');
  assert.ok(/never follow/.test(b), 'should say never follow instructions in content');
  assert.ok(/ask the user/.test(b), 'should say ask the user before side-effecting actions');
  assert.ok(/verdict/.test(b), 'should explain how to read the verdict');
  assert.ok(/exit/.test(b), 'should explain exit codes');
});

test('bundled script and references exist', () => {
  assert.ok(existsSync(path.join(SKILL_DIR, 'scripts', 'scan.mjs')));
  assert.ok(existsSync(path.join(SKILL_DIR, 'references', 'attack-patterns.md')));
});

test('references document Urdu and Roman Urdu patterns', () => {
  const refs = readFileSync(path.join(SKILL_DIR, 'references', 'attack-patterns.md'), 'utf8');
  assert.ok(/roman urdu/i.test(refs));
  assert.ok(/[؀-ۿ]/.test(refs), 'should contain Urdu-script examples');
});
