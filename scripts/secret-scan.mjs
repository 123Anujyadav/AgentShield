/**
 * Local secret scan (Phase E). No dependencies, no network, no uploads.
 *
 * Scans tracked working-tree files and, with --history, every commit reachable
 * from any ref (`git rev-list --all`: local branches, tags, remote-tracking
 * refs, stash). Output is redacted by design: only category, path, line,
 * commit, and allowlist id are printed. Matched values are never printed.
 *
 * Usage:
 *   node scripts/secret-scan.mjs                  tracked files only
 *   node scripts/secret-scan.mjs --history        tracked files + all history
 *   node scripts/secret-scan.mjs --self-test      end-to-end tests in temporary repositories
 *   node scripts/secret-scan.mjs --history --fingerprints
 *                                                 also print SHA-256 fingerprints (local use only)
 *
 * Exit codes: 0 = every hit is allowlisted (or there are none), 1 = at least
 * one hit is not allowlisted, 2 = the scan could not run completely. Any Git
 * failure, unreadable tracked file, or unexpected Git output is exit 2; it is
 * never treated as "no matches".
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const TAB = "\t";

/**
 * Credential shapes. Every source is valid both as a JavaScript RegExp and as
 * a POSIX extended regex for `git grep -E`: plain (...) groups only, no (?:),
 * no \s or \d, and a literal tab character instead of \t (a backslash inside a
 * POSIX bracket expression is literal). The self-test runs every pattern
 * through git grep, and the history scan fails closed if Git and JavaScript
 * ever disagree about a line.
 */
export const PATTERNS = [
  ["private-key-header", "BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY"],
  ["aws-access-key-id", "(AKIA|ASIA)[0-9A-Z]{16}"],
  ["github-token", "(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}"],
  ["gitlab-token", "glpat-[A-Za-z0-9_-]{20,}"],
  ["sk-style-token", "sk-(proj-|ant-)?[A-Za-z0-9_-]{24,}"],
  ["stripe-live-key", "(sk|rk)_live_[0-9A-Za-z]{24,}"],
  ["slack-token", "xox[abposr]-[A-Za-z0-9-]{10,}"],
  ["google-api-key", "AIza[0-9A-Za-z_-]{35}"],
  ["bearer-token", `Bearer[ ${TAB}]+[A-Za-z0-9._-]{24,}`],
  ["model-api-key-assignment", `MODEL_API_KEY[ ${TAB}]*=[ ${TAB}]*[A-Za-z0-9][A-Za-z0-9_-]{7,}`],
].map(([category, source]) => ({ category, source }));

/**
 * Reviewed allowlist. Each entry matches exactly one matched value (SHA-256 of
 * "category\0value"), never a file, path, or word. Every entry here is an
 * invented value used by the detector's own tests and benchmark fixtures, and
 * it stays in history, so annotations cannot be added to it. Allowlisted hits
 * are still printed as ALLOWLISTED. To add an entry, review the value, run
 * --fingerprints locally, and copy only the fingerprint.
 */
export const ALLOWLIST = [
  {
    id: "engine-test-bearer-alphabet",
    category: "bearer-token",
    fingerprint: "3caf7c50cf15fa4a3a675f1b1463840de163b629a0639d367a514d181fc0a6cb",
    reason: "Invented value (lowercase alphabet) in packages/engine/src/evaluate.test.ts",
  },
  {
    id: "engine-test-sk-ant-fakefake",
    category: "sk-style-token",
    fingerprint: "9c8cb2631d04a4c7408bbf6b2dbd2d65da0a5eba4f56bf4bc1faef9cc6b1535b",
    reason: "Invented FAKEFAKE sk-ant value in packages/engine/src/evaluate.test.ts",
  },
  {
    id: "benchmark-tok-01-bearer",
    category: "bearer-token",
    fingerprint: "768aef2ba684506b6a785a5d1d0e7216efbd2bb402f023b14d506d5b687580bc",
    reason: "Invented fakeBenchmark Bearer value, fixture tok-01 in benchmarks/detection/*/fixtures.json",
  },
  {
    id: "benchmark-tok-02-sk-proj",
    category: "sk-style-token",
    fingerprint: "bb14bc234e5f977cb8228840c353b5271e424d0660a855001c055bbaa6a6389b",
    reason: "Invented fakeBenchmark sk-proj value, fixture tok-02 in benchmarks/detection/*/fixtures.json",
  },
  {
    id: "benchmark-tok-03-sk-ant",
    category: "sk-style-token",
    fingerprint: "25b43f6bb92a438f4e1b5c05b13b2f7c8bcda03e76df063862593c0418a7d982",
    reason: "Invented fakeBenchmark sk-ant value, fixture tok-03 in benchmarks/detection/*/fixtures.json",
  },
  {
    id: "benchmark-f-02-sk-proj",
    category: "sk-" + "style-token",
    fingerprint: "9e98e94f851c6f7349ce7d7ae8daf62d632c6339643d8ac1147caeeeffff36f1",
    reason: "Invented fakeBenchmark sk-proj destination value, fixture f-02 in benchmarks/detection/v1.5/fixtures.json",
  },
  {
    id: "benchmark-f-03-bearer",
    category: "bearer-token",
    fingerprint: "a2d4dcc786d695260eae795ab2cc9d246b5cc23149561ec89335f0070c67ea26",
    reason: "Invented fakeBenchmark Bearer destination value, fixture f-03 in benchmarks/detection/v1.5/fixtures.json",
  },
  {
    id: "benchmark-m-02-bearer",
    category: "bearer-token",
    fingerprint: "fec594e2f52978d490e04376ee4acb80c7618db63043c9863a8158f2d3e677d9",
    reason: "Invented fakeBenchmark Bearer tool value, fixture m-02 in benchmarks/detection/v1.8/fixtures.json",
  },
];

/** Protected dataset payloads: Git is told never to read them. */
const PROTECTED_PATHSPECS = [
  ":(exclude,glob)ml/datasets/sentinel/*/samples.jsonl",
  ":(exclude,glob)ml/datasets/sentinel/*/splits/**",
];
const PROTECTED_PATH = /^ml\/datasets\/sentinel\/[^/]+\/(samples\.jsonl$|splits\/)/;

class ScanError extends Error {}

/** Redacts anything credential-shaped and keeps one short line, for error messages. */
function safeMessage(text) {
  let line = String(text ?? "").split(/\r?\n/).find((l) => l.trim()) ?? "";
  for (const { source } of PATTERNS) line = line.replace(new RegExp(source, "g"), "[REDACTED]");
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

function fingerprint(category, value) {
  return createHash("sha256").update(`${category}\0${value}`).digest("hex");
}

/** Every credential-shaped match on one line, with its allowlist decision. */
export function classifyLine(line, allowlist = ALLOWLIST) {
  const hits = [];
  for (const { category, source } of PATTERNS) {
    for (const match of line.matchAll(new RegExp(source, "g"))) {
      const fp = fingerprint(category, match[0]);
      const entry = allowlist.find((a) => a.category === category && a.fingerprint === fp);
      hits.push({ category, fingerprint: fp, allowlistId: entry?.id ?? null });
    }
  }
  return hits;
}

/** Runs git and returns stdout; any failure, non-allowed status, or stderr output throws. */
function runGit(cwd, args, allowedStatus = [0]) {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, windowsHide: true });
  const what = `git ${args[0]}`;
  if (result.error) throw new ScanError(`${what} could not run (${result.error.code ?? safeMessage(result.error.message)})`);
  if (result.signal) throw new ScanError(`${what} was terminated by ${result.signal}`);
  if (!allowedStatus.includes(result.status)) {
    throw new ScanError(`${what} failed with status ${result.status}: ${safeMessage(result.stderr)}`);
  }
  if (result.stderr && result.stderr.trim()) {
    throw new ScanError(`${what} reported an error (status ${result.status}): ${safeMessage(result.stderr)}`);
  }
  return { stdout: result.stdout, status: result.status };
}

function nulList(text) {
  if (text && !text.endsWith("\0")) throw new ScanError("unexpected git output: list not NUL-terminated");
  return text ? text.slice(0, -1).split("\0") : [];
}

function scanWorktree(top, allowlist) {
  const files = nulList(runGit(top, ["ls-files", "-z", "--", ".", ...PROTECTED_PATHSPECS]).stdout);
  const deleted = new Set(nulList(runGit(top, ["ls-files", "-z", "-d", "--", ".", ...PROTECTED_PATHSPECS]).stdout));
  const findings = [];
  const errors = [];
  let scanned = 0;
  let binary = 0;
  for (const file of files) {
    if (PROTECTED_PATH.test(file)) throw new ScanError("git listed a protected dataset path despite the exclusion");
    if (deleted.has(file)) continue; // Reported below; nothing on disk to read.
    let buffer;
    try {
      buffer = readFileSync(join(top, file));
    } catch (error) {
      errors.push(`${file}: ${error.code ?? "read error"}`);
      continue;
    }
    if (buffer.includes(0)) {
      binary += 1;
      continue;
    }
    scanned += 1;
    buffer.toString("utf8").split(/\r?\n/).forEach((line, index) => {
      for (const hit of classifyLine(line, allowlist)) findings.push({ where: `${file}:${index + 1}`, ...hit });
    });
  }
  return { findings, errors, scanned, binary, deleted: deleted.size };
}

/** Parses `git grep -n --null` output: "<rev>:<path>\0<line>\0<content>\n" per hit. */
export function parseGrepOutput(out, rev) {
  const records = [];
  const prefix = `${rev}:`;
  let i = 0;
  while (i < out.length) {
    if (!out.startsWith(prefix, i)) throw new ScanError("unexpected git grep output: missing revision prefix");
    const pathEnd = out.indexOf("\0", i + prefix.length);
    const lineEnd = pathEnd === -1 ? -1 : out.indexOf("\0", pathEnd + 1);
    const recordEnd = lineEnd === -1 ? -1 : out.indexOf("\n", lineEnd + 1);
    if (recordEnd === -1) throw new ScanError("unexpected git grep output: truncated record");
    const path = out.slice(i + prefix.length, pathEnd);
    const lineNo = out.slice(pathEnd + 1, lineEnd);
    if (!path || !/^[0-9]+$/.test(lineNo)) throw new ScanError("unexpected git grep output: malformed record");
    records.push({ path, lineNo: Number(lineNo), content: out.slice(lineEnd + 1, recordEnd) });
    i = recordEnd + 1;
  }
  return records;
}

/** All hits in one revision. Exit status 1 is the only "no matches" result. */
export function grepRevision(top, rev, sources) {
  const args = ["grep", "-I", "-n", "--null", "-E", ...sources.flatMap((s) => ["-e", s]), rev, "--", ".", ...PROTECTED_PATHSPECS];
  const { stdout, status } = runGit(top, args, [0, 1]);
  if (status === 1) {
    if (stdout) throw new ScanError("unexpected git grep output: status 1 with output");
    return [];
  }
  if (!stdout) throw new ScanError("unexpected git grep output: status 0 without output");
  return parseGrepOutput(stdout, rev);
}

function scanHistory(top, allowlist) {
  const revs = runGit(top, ["rev-list", "--all"]).stdout.split("\n").filter(Boolean);
  if (revs.some((rev) => !/^[0-9a-f]{40,64}$/.test(rev))) throw new ScanError("unexpected git rev-list output");
  const findings = [];
  for (const rev of revs) {
    for (const record of grepRevision(top, rev, PATTERNS.map((p) => p.source))) {
      if (PROTECTED_PATH.test(record.path)) throw new ScanError("git searched a protected dataset path despite the exclusion");
      const hits = classifyLine(record.content, allowlist);
      // Git reported this line, so the same patterns must match it here too.
      if (hits.length === 0) throw new ScanError("git grep and the scanner disagree about a matched line");
      for (const hit of hits) findings.push({ where: `${rev.slice(0, 12)}:${record.path}:${record.lineNo}`, ...hit });
    }
  }
  return { findings, commits: revs.length };
}

function report(label, findings, showFingerprints) {
  for (const f of findings) {
    const status = f.allowlistId ? `ALLOWLISTED [${f.allowlistId}]` : "FINDING";
    const fp = showFingerprints ? ` fingerprint=${f.fingerprint}` : "";
    console.log(`${status} ${f.category} at ${f.where}${fp} (value redacted)`);
  }
  const failing = findings.filter((f) => !f.allowlistId).length;
  console.log(`${label}: ${failing} not allowlisted, ${findings.length - failing} allowlisted`);
  return failing;
}

function scan({ history, fingerprints }) {
  const top = runGit(process.cwd(), ["rev-parse", "--show-toplevel"]).stdout.trim();
  if (!top) throw new ScanError("unexpected git rev-parse output");
  let failing = 0;
  const worktree = scanWorktree(top, ALLOWLIST);
  console.log(
    `worktree: scanned ${worktree.scanned} tracked text files` +
      ` (${worktree.binary} binary skipped, ${worktree.deleted} deleted in the working tree)`,
  );
  failing += report("worktree findings", worktree.findings, fingerprints);
  if (history) {
    const past = scanHistory(top, ALLOWLIST);
    console.log(`history: scanned ${past.commits} commits reachable from any ref`);
    failing += report("history findings", past.findings, fingerprints);
  }
  if (worktree.errors.length > 0) {
    for (const error of worktree.errors) console.error(`unreadable tracked file: ${error}`);
    throw new ScanError(`${worktree.errors.length} tracked file(s) could not be read`);
  }
  if (failing > 0) {
    console.error(`secret scan FAILED: ${failing} credential-shaped value(s) not on the allowlist (values redacted)`);
    process.exit(1);
  }
  console.log("secret scan passed: every credential-shaped value found is on the reviewed allowlist");
}

/* ------------------------------------------------------------------ */
/* Self-test: drives this CLI against throwaway repositories in the   */
/* OS temp directory. Fake values are built at runtime, never printed. */
/* ------------------------------------------------------------------ */

function fakeValues() {
  const z = (n) => "Z".repeat(n);
  return {
    "private-key-header": `-----BEGIN RSA ${"PRIVATE"} KEY-----`,
    "aws-access-key-id": `${"AK"}IA${z(16)}`,
    "github-token": `${"ghp"}_${z(36)}`,
    "gitlab-token": `${"glpat"}-${z(24)}`,
    "sk-style-token": `${"sk"}-${z(30)}`,
    "stripe-live-key": `${"sk_live"}_${z(24)}`,
    "slack-token": `${"xoxb"}-${z(20)}`,
    "google-api-key": `${"AI"}za${z(35)}`,
    "bearer-token": `${"Bear"}er ${z(30)}`,
    "model-api-key-assignment": `${"MODEL_API"}_KEY=${z(12)}`,
  };
}

function selfTest() {
  const script = fileURLToPath(import.meta.url);
  const fake = fakeValues();
  const secrets = Object.values(fake);
  const root = mkdtempSync(join(tmpdir(), "secret-scan-selftest-"));
  let failures = 0;
  let checks = 0;
  const check = (name, ok) => {
    checks += 1;
    if (!ok) failures += 1;
    console.log(`${ok ? "ok  " : "FAIL"} ${name}`);
  };
  const git = (cwd, ...args) =>
    spawnSync("git", ["-c", "core.autocrlf=false", "-c", "user.name=selftest", "-c", "user.email=selftest@invalid", "-c", "commit.gpgsign=false", ...args], { cwd, encoding: "utf8" });
  let repoCount = 0;
  const repo = (files) => {
    const dir = join(root, `repo-${(repoCount += 1)}`);
    mkdirSync(dir);
    git(dir, "init", "-q");
    for (const [path, text] of Object.entries(files)) {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), text);
    }
    git(dir, "add", "--all");
    git(dir, "commit", "-q", "--allow-empty", "-m", "fixture");
    return dir;
  };
  const cli = (cwd, args = [], env = process.env) => {
    const r = spawnSync(process.execPath, [script, ...args], { cwd, env, encoding: "utf8" });
    const output = `${r.stdout}${r.stderr}`;
    // No fake value, or any 10-character run of its padding, may ever be printed.
    const leaked = secrets.some((s) => output.includes(s)) || output.includes("Z".repeat(10));
    return { status: r.status, output, leaked };
  };
  const expectFinding = (name, result, category, where) =>
    check(name, result.status === 1 && !result.leaked && result.output.includes(`FINDING ${category} at ${where}`));

  try {
    // H-1: no file name or ordinary word suppresses a finding.
    const aws = fake["aws-access-key-id"];
    expectFinding("normal file fails", cli(repo({ "config.js": `const k = "${aws}";\n` })), "aws-access-key-id", "config.js:1");
    expectFinding("test file fails", cli(repo({ "src/config.test.ts": `const k = "${aws}";\n` })), "aws-access-key-id", "src/config.test.ts:1");
    expectFinding("fixture file fails", cli(repo({ "bench/fixtures.json": `{"k": "${aws}"}\n` })), "aws-access-key-id", "bench/fixtures.json:1");
    for (const word of ["latest", "contest", "attestation", "fake test example benchmark placeholder"]) {
      expectFinding(`line containing "${word}" fails`, cli(repo({ "notes.txt": `${fake["sk-style-token"]} ${word}\n` })), "sk-style-token", "notes.txt:1");
    }

    // Every pattern, through both the working-tree and the history scan.
    const lines = Object.values(fake).join("\n");
    const allRepo = repo({ "all.txt": `${lines}\n` });
    const worktreeAll = cli(allRepo);
    const historyAll = cli(allRepo, ["--history"]);
    for (const [i, category] of Object.keys(fake).entries()) {
      check(`worktree detects ${category}`, worktreeAll.output.includes(`FINDING ${category} at all.txt:${i + 1}`));
      check(`history (git grep) detects ${category}`, new RegExp(`FINDING ${category} at [0-9a-f]{12}:all\\.txt:${i + 1} `).test(historyAll.output));
    }
    check("all-pattern scans exit 1 without printing values", worktreeAll.status === 1 && historyAll.status === 1 && !worktreeAll.leaked && !historyAll.leaked);

    // H-2: a credential committed and later deleted is found in history only.
    const deletedRepo = repo({
      "leak.txt": ["private-key-header", "github-token", "sk-style-token", "aws-access-key-id"].map((c) => fake[c]).join("\n") + "\n",
    });
    git(deletedRepo, "rm", "-q", "leak.txt");
    git(deletedRepo, "commit", "-q", "-m", "remove");
    const afterDelete = cli(deletedRepo);
    check("deleted credential: working-tree scan passes", afterDelete.status === 0 && !afterDelete.leaked);
    const deletedHistory = cli(deletedRepo, ["--history"]);
    for (const category of ["private-key-header", "github-token", "sk-style-token", "aws-access-key-id"]) {
      check(`deleted credential: history finds ${category}`, deletedHistory.status === 1 && deletedHistory.output.includes(`FINDING ${category} at `));
    }
    check("deleted credential: history output is redacted", !deletedHistory.leaked);

    // Clean history passes only through git grep's "no matches" status 1.
    const clean = cli(repo({ "readme.md": "nothing to see\n" }), ["--history"]);
    check("clean history passes", clean.status === 0 && /history: scanned 1 commits/.test(clean.output));
    const cleanTop = join(root, `repo-${repoCount}`);
    check("no-match git grep returns []", grepRevision(cleanTop, "HEAD", PATTERNS.map((p) => p.source)).length === 0);

    // Fail closed: invalid regex, corrupt history, unreadable file, missing git.
    let invalidThrows = false;
    try {
      grepRevision(cleanTop, "HEAD", ["a(?:b)"]);
    } catch (error) {
      invalidThrows = error instanceof ScanError;
    }
    check("invalid regex is an error, not 'no matches'", invalidThrows);

    const corrupt = repo({ "data.txt": "plain text\n" });
    const blob = git(corrupt, "rev-parse", "HEAD:data.txt").stdout.trim();
    const objectFile = join(corrupt, ".git", "objects", blob.slice(0, 2), blob.slice(2));
    chmodSync(objectFile, 0o666); // Git writes objects read-only; Windows refuses to delete those.
    unlinkSync(objectFile);
    check("corrupt history (missing object) exits 2", cli(corrupt, ["--history"]).status === 2);

    const unreadable = repo({ "gone.txt": "plain\n" });
    rmSync(join(unreadable, "gone.txt"));
    mkdirSync(join(unreadable, "gone.txt"));
    check("unreadable tracked file exits 2", cli(unreadable).status === 2);

    const deletedOnly = repo({ "keep.txt": "plain\n", "removed.txt": "plain\n" });
    rmSync(join(deletedOnly, "removed.txt"));
    const deletedResult = cli(deletedOnly);
    check("file deleted in the working tree is reported, not an error", deletedResult.status === 0 && /1 deleted in the working tree/.test(deletedResult.output));

    const noGitEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !/^path$/i.test(key)));
    noGitEnv.PATH = "";
    check("missing git exits 2", cli(cleanTop, [], noGitEnv).status === 2);
    check("outside a repository exits 2", cli(root, [], { ...process.env, GIT_CEILING_DIRECTORIES: root }).status === 2);

    // M-1: spaces and non-ASCII file names are read, in both scans.
    const unicodeRepo = repo({ "dir é/cfg ü.js": `const t = "${fake["github-token"]}";\n` });
    expectFinding("non-ASCII and spaced file name: working tree", cli(unicodeRepo), "github-token", "dir é/cfg ü.js:1");
    check("non-ASCII and spaced file name: history", /FINDING github-token at [0-9a-f]{12}:dir é\/cfg ü\.js:1 /.test(cli(unicodeRepo, ["--history"]).output));

    // Allowlist: exact fingerprint only, never another value or a file.
    const value = fake["sk-style-token"];
    const entry = { id: "selftest", category: "sk-style-token", fingerprint: fingerprint("sk-style-token", value) };
    check("allowlisted fingerprint is reported as allowlisted", classifyLine(value, [entry])[0]?.allowlistId === "selftest");
    check("a different value is not allowlisted", classifyLine(value.replace(/Z$/, "Y"), [entry])[0]?.allowlistId === null);

    // Parser fails closed on malformed output.
    let malformed = 0;
    for (const bad of ["HEAD:a.txt\u00001\u0000line", "HEAD:a.txt\u0000x\u0000line\n", "OTHER:a.txt\u00001\u0000line\n"]) {
      try {
        parseGrepOutput(bad, "HEAD");
      } catch (error) {
        if (error instanceof ScanError) malformed += 1;
      }
    }
    check("malformed git grep output is an error", malformed === 3);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  if (existsSync(root)) console.log("note: temporary self-test directory could not be removed");
  if (failures > 0) {
    console.error(`self-test FAILED: ${failures} of ${checks} checks failed (values never printed)`);
    process.exit(1);
  }
  console.log(`self-test passed: ${checks} checks, values never printed`);
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes("--self-test")) return selfTest();
  return scan({ history: args.includes("--history"), fingerprints: args.includes("--fingerprints") });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    const message = error instanceof ScanError ? error.message : safeMessage(error instanceof Error ? error.message : error);
    console.error(`secret scan ERROR: could not complete (${message})`);
    process.exit(2);
  }
}
