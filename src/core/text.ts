/** Small text utilities shared by every scanner. Kept dependency-free on purpose. */

export interface LineHit {
  line: number;
  column: number;
  text: string;
}

/** Map a character offset to a 1-indexed line, column, and the full line text. */
export function lineOf(text: string, index: number): LineHit {
  let line = 1;
  let lineStart = 0;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") {
      line++;
      lineStart = i + 1;
    }
  }
  let lineEnd = text.indexOf("\n", lineStart);
  if (lineEnd === -1) lineEnd = text.length;
  return { line, column: index - lineStart + 1, text: text.slice(lineStart, lineEnd) };
}

/** Iterate a global regex safely, resetting state and guarding against zero-length loops. */
export function* matches(re: RegExp, text: string): Generator<RegExpExecArray> {
  const rx = re.global ? re : new RegExp(re.source, `${re.flags}g`);
  rx.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = rx.exec(text)) !== null) {
    if (m[0].length === 0) rx.lastIndex++;
    if (++guard > 20_000) break;
    yield m;
  }
}

/** True when the offset sits inside a line-comment or a block comment. */
export function inComment(text: string, index: number): boolean {
  const { text: lineText, column } = lineOf(text, index);
  const before = lineText.slice(0, column - 1);
  if (/(^|[^:])\/\/|^\s*#|^\s*--|^\s*\*|^\s*\/\*/.test(before)) return true;
  const upto = text.slice(0, index);
  const openBlock = upto.lastIndexOf("/*");
  const closeBlock = upto.lastIndexOf("*/");
  return openBlock > closeBlock;
}

/**
 * True when the offset sits inside a regular-expression literal.
 *
 * This matters far beyond self-scanning. Validators, sanitizers, linters,
 * log-scrubbers, and WAF rules all contain literal patterns that look exactly
 * like the vulnerability they exist to prevent -- a password-strength checker
 * contains a weak-password pattern, a redaction library contains every API-key
 * shape there is. Flagging those is the most annoying possible false positive,
 * because it fires hardest on the code written by the most security-conscious
 * teams.
 *
 * Distinguishing regex literals from division is undecidable without a real
 * parser, so this is a heuristic tuned to be conservative: it requires a
 * plausible opening delimiter before the match and a closing delimiter with
 * regex flags after it, on the same line.
 */
export function inRegexLiteral(text: string, index: number): boolean {
  const { text: line, column } = lineOf(text, index);
  const before = line.slice(0, column - 1);
  const after = line.slice(column - 1);

  // A property that conventionally holds a pattern.
  if (/\b(?:re|regex|regexp|pattern|matcher)\s*:\s*\/|new RegExp\s*\(/.test(before)) return true;

  // An unescaped `/` opening a literal in a position where a regex is legal.
  const opener = /(?:^|[=(,:[!&|?{;+]|=>|\breturn|\btest\(|\bmatch\(|\breplace\()\s*\/(?![/*])/.exec(before);
  if (!opener) return false;

  // A closing `/` with flags after the match.
  return /\/[dgimsuvy]*\s*(?:[,)\];}]|$)/.test(after);
}

export function extname(file: string): string {
  const i = file.lastIndexOf(".");
  return i === -1 ? "" : file.slice(i).toLowerCase();
}

export function basename(file: string): string {
  const i = file.lastIndexOf("/");
  return i === -1 ? file : file.slice(i + 1);
}

/** Language label for a path, used for syntax hints in remediation snippets. */
export function languageOf(file: string): string {
  const map: Record<string, string> = {
    ".ts": "typescript", ".tsx": "tsx", ".js": "javascript", ".jsx": "jsx",
    ".mjs": "javascript", ".cjs": "javascript", ".py": "python", ".rb": "ruby",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "kotlin", ".cs": "csharp",
    ".php": "php", ".sql": "sql", ".sh": "bash", ".yml": "yaml", ".yaml": "yaml",
    ".tf": "hcl", ".json": "json", ".vue": "vue", ".svelte": "svelte", ".astro": "astro",
  };
  return map[extname(file)] ?? "text";
}

/** True for files whose contents are compiled into a browser bundle. */
export function isClientReachable(file: string, text?: string): boolean {
  if (text && /^\s*['"]use client['"]/m.test(text)) return true;
  if (/\.(?:jsx|tsx|vue|svelte|astro)$/i.test(file)) return true;
  return /(?:^|\/)(?:public|static|assets|client|components?|pages|views?|www)(?:\/|$)/i.test(file);
}

/** True when a server-only marker makes a file definitively non-client. */
export function isServerOnly(file: string, text?: string): boolean {
  if (text && /^\s*['"]use server['"]|import\s+['"]server-only['"]/m.test(text)) return true;
  return /(?:^|\/)(?:api|server|backend|functions|lambda|worker|routes?)(?:\/|$)|route\.(?:ts|js)$|\.server\.(?:ts|js)$/i.test(
    file,
  );
}

export function isTestFile(file: string): boolean {
  return /(?:^|\/)(?:tests?|__tests__|spec|specs|fixtures?|mocks?|e2e|cypress|playwright)(?:\/|$)|\.(?:test|spec|stories)\.[a-z]+$/i.test(
    file,
  );
}
