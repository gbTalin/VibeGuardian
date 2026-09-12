#!/usr/bin/env node
// Guardian Unit launcher. Node >= 22.18 strips TypeScript types natively, so there is
// no build step and no bundler in the supply chain.
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const major = Number(process.versions.node.split(".")[0]);
const minor = Number(process.versions.node.split(".")[1]);
if (major < 22 || (major === 22 && minor < 18)) {
  console.error(
    `Guardian Unit needs Node 22.18 or newer (you have ${process.versions.node}).\n` +
      `Install a current Node from https://nodejs.org and try again.`
  );
  process.exit(1);
}

const here = dirname(fileURLToPath(import.meta.url));
await import(join(here, "..", "src", "cli.ts"));
