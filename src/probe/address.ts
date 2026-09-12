import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { ProbeRefusal, type AuthorizedTarget } from "./authorization.ts";

export interface ResolvedAddress {
  address: string;
  family: 4 | 6;
}

export interface ResolvedTarget {
  target: AuthorizedTarget;
  addresses: ResolvedAddress[];
  pinned: ResolvedAddress;
}

function hostWithoutBrackets(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
}

function ipv4Parts(address: string): number[] | null {
  if (isIP(address) !== 4) return null;
  const parts = address.split(".").map(Number);
  return parts.length === 4 ? parts : null;
}

function inV4(parts: number[], a: number, bMin = 0, bMax = 255): boolean {
  return parts[0] === a && parts[1] >= bMin && parts[1] <= bMax;
}

export function isLoopbackAddress(address: string): boolean {
  const normalized = hostWithoutBrackets(address).toLowerCase();
  const v4 = ipv4Parts(normalized);
  return v4 ? v4[0] === 127 : normalized === "::1" || normalized.startsWith("::ffff:127.");
}

/** Conservative classification: unknown special ranges are denied, not guessed public. */
export function isForbiddenAddress(address: string): boolean {
  const normalized = hostWithoutBrackets(address).toLowerCase().split("%")[0];
  const v4 = ipv4Parts(normalized);
  if (v4) {
    const [a, b] = v4;
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      inV4(v4, 100, 64, 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || b === 51)) ||
      (a === 203 && b === 0 && v4[2] === 113) ||
      a >= 224
    );
  }
  if (isIP(normalized) !== 6) return true;
  if (normalized.startsWith("::ffff:")) return isForbiddenAddress(normalized.slice(7));
  return (
    normalized === "::" ||
    normalized === "::1" ||
    /^f[cd]/.test(normalized) ||
    /^fe[89ab]/.test(normalized) ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:") ||
    normalized === "2001:db8::" ||
    normalized.startsWith("100:") ||
    normalized.startsWith("2001:10:")
  );
}

function literalFamily(hostname: string): 0 | 4 | 6 {
  return isIP(hostWithoutBrackets(hostname)) as 0 | 4 | 6;
}

export async function resolveApprovedTarget(target: AuthorizedTarget): Promise<ResolvedTarget> {
  const hostname = hostWithoutBrackets(target.url.hostname);
  const literal = literalFamily(hostname);
  const localNames = new Set(["localhost", "127.0.0.1", "::1"]);

  if (target.environment === "local" && !localNames.has(hostname.toLowerCase())) {
    throw new ProbeRefusal("local mode permits only localhost, 127.0.0.1, or ::1.");
  }
  if (target.environment === "production" && literal !== 0) {
    throw new ProbeRefusal("production targets cannot be IP literals.");
  }

  let addresses: ResolvedAddress[];
  if (literal !== 0) {
    addresses = [{ address: hostname, family: literal }];
  } else {
    const resolved = await lookup(hostname, { all: true, verbatim: true });
    addresses = resolved
      .filter((entry): entry is typeof entry & { family: 4 | 6 } => entry.family === 4 || entry.family === 6)
      .map((entry) => ({ address: entry.address, family: entry.family }));
  }
  if (addresses.length === 0) throw new Error("DNS returned no usable A or AAAA address.");
  const unique = [...new Map(addresses.map((entry) => [`${entry.family}:${entry.address}`, entry])).values()];

  if (target.environment === "local") {
    if (unique.some((entry) => !isLoopbackAddress(entry.address))) {
      throw new ProbeRefusal("local target resolved outside loopback.");
    }
  } else if (unique.some((entry) => isForbiddenAddress(entry.address))) {
    throw new ProbeRefusal("target resolved to a private, loopback, link-local, reserved, or documentation address.");
  }

  return { target, addresses: unique, pinned: unique[0] };
}
