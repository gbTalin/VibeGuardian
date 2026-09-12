import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";

/**
 * File discovery.
 *
 * Two goals in tension: scan enough to be useful, skip enough to be fast and to
 * avoid drowning in vendored code. The skip list is deliberately conservative --
 * anything skipped is reported in the coverage section, because a scanner that
 * quietly ignores half a repo and then reports "no issues found" is worse than
 * no scanner at all.
 */

/** Directories never worth scanning: vendored code, build output, VCS internals. */
export const SKIP_DIRS = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "bower_components",
  "vendor",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".svelte-kit",
  ".turbo",
  ".cache",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".tox",
  "venv",
  ".venv",
  "env",
  "target",
  ".gradle",
  ".idea",
  ".vscode",
  "coverage",
  ".nyc_output",
  "Pods",
  "DerivedData",
  ".terraform",
  ".serverless",
  ".guardian-unit",
]);

/** Extensions that are binary or generated and carry no useful signal. */
const SKIP_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico", ".bmp", ".tiff", ".svg",
  ".mp3", ".mp4", ".wav", ".mov", ".avi", ".mkv", ".webm", ".flac", ".ogg",
  ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".dmg", ".iso",
  ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
  ".woff", ".woff2", ".ttf", ".otf", ".eot",
  ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a", ".class", ".pyc", ".wasm",
  ".map", ".lock",
  ".mo", ".po",
]);

/**
 * Lockfiles are skipped by the text walkers but read explicitly by the
 * dependency scanner, which knows how to parse them.
 */
export const LOCKFILES = new Set([
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lockb",
  "poetry.lock",
  "Pipfile.lock",
  "Cargo.lock",
  "go.sum",
  "composer.lock",
  "Gemfile.lock",
]);

const MAX_FILE_BYTES = 2 * 1024 * 1024; // 2 MB. Bigger files are minified bundles or data.

export interface WalkResult {
  files: string[];
  skipped: number;
  skipReasons: Record<string, number>;
}

export interface WalkOptions {
  maxFiles?: number;
  /** Extra glob-ish prefixes to ignore, from .guardianignore or config. */
  extraIgnores?: string[];
  signal?: AbortSignal;
}

function extOf(name: string): string {
  const i = name.lastIndexOf(".");
  return i === -1 ? "" : name.slice(i).toLowerCase();
}

/**
 * Read .gitignore-style ignore entries. Intentionally supports only the common
 * subset (plain paths and a single trailing wildcard); full gitignore semantics
 * are not worth a dependency, and anything we fail to ignore is merely scanned,
 * not mishandled.
 */
export async function readIgnoreFile(root: string): Promise<string[]> {
  const out: string[] = [];
  for (const name of [".guardianignore", ".gitignore"]) {
    try {
      const text = await readFile(join(root, name), "utf8");
      for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t.startsWith("#") || t.startsWith("!")) continue;
        out.push(t.replace(/^\/+/, "").replace(/\/+$/, ""));
      }
    } catch {
      /* absent is fine */
    }
  }
  return out;
}

function ignored(relPath: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false;
  const parts = relPath.split(sep);
  for (const p of patterns) {
    if (p.includes("*")) {
      const rx = new RegExp(`^${p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*")}$`);
      if (parts.some((seg) => rx.test(seg))) return true;
    } else if (parts.includes(p) || relPath === p || relPath.startsWith(`${p}${sep}`)) {
      return true;
    }
  }
  return false;
}

export async function walk(root: string, opts: WalkOptions = {}): Promise<WalkResult> {
  const maxFiles = opts.maxFiles ?? 60_000;
  const patterns = opts.extraIgnores ?? [];
  const files: string[] = [];
  const skipReasons: Record<string, number> = {};
  let skipped = 0;

  const bump = (reason: string) => {
    skipped++;
    skipReasons[reason] = (skipReasons[reason] ?? 0) + 1;
  };

  const queue: string[] = [root];
  while (queue.length > 0) {
    if (opts.signal?.aborted) break;
    const dir = queue.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      bump("unreadable directory");
      continue;
    }
    for (const e of entries) {
      if (files.length >= maxFiles) {
        bump("file limit reached");
        continue;
      }
      const abs = join(dir, e.name);
      const rel = relative(root, abs);

      if (e.isSymbolicLink()) {
        // Not followed. A symlink out of the scan root is a directory-traversal
        // vector and, in a monorepo, an easy way to scan the same tree twice.
        bump("symlink (not followed)");
        continue;
      }
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) {
          bump(`vendored or generated directory (${e.name})`);
          continue;
        }
        if (ignored(rel, patterns)) {
          bump("matched ignore file");
          continue;
        }
        queue.push(abs);
        continue;
      }
      if (!e.isFile()) continue;
      if (ignored(rel, patterns)) {
        bump("matched ignore file");
        continue;
      }
      const ext = extOf(e.name);
      if (SKIP_EXT.has(ext) && !LOCKFILES.has(e.name)) {
        bump("binary or non-source file");
        continue;
      }
      try {
        const st = await stat(abs);
        if (st.size > MAX_FILE_BYTES) {
          bump("file larger than 2 MB");
          continue;
        }
        if (st.size === 0) continue;
      } catch {
        bump("unreadable file");
        continue;
      }
      files.push(rel);
    }
  }

  files.sort();
  return { files, skipped, skipReasons };
}

/** Heuristic binary sniff, so a mislabelled extension does not poison a scanner. */
export function looksBinary(buf: Buffer): boolean {
  const n = Math.min(buf.length, 1024);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}
