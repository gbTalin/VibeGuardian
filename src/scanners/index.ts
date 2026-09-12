import { Engine } from "../core/engine.ts";
import { secretsScanner } from "./secrets.ts";
import { aiCodeScanner } from "./ai-code.ts";
import { aiAgentScanner } from "./ai-agents.ts";
import { dependencyScanner } from "./dependencies.ts";
import { iacScanner } from "./iac.ts";
import { ciScanner } from "./ci.ts";
import { codeScanner } from "./code.ts";

/**
 * The scanner roster.
 *
 * Order here is the order shown in the UI, chosen so the checks a first-time
 * user cares about most appear first.
 */
export function buildEngine(): Engine {
  return new Engine().register(
    secretsScanner,
    aiCodeScanner,
    aiAgentScanner,
    dependencyScanner,
    ciScanner,
    iacScanner,
    codeScanner,
  );
}

export const ALL_SCANNERS = [
  secretsScanner,
  aiCodeScanner,
  aiAgentScanner,
  dependencyScanner,
  ciScanner,
  iacScanner,
  codeScanner,
];
