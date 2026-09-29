/**
 * Flocta Code — the confirmation policy (Flocta AC 10.1.3, ADR 0042 §3.5, D-341).
 *
 * Upstream OpenCode allows every tool by default (`"*": "allow"`), so a file
 * write or a shell command runs unless the user configured otherwise, and an
 * "always" approval lasts for the whole running instance. Flocta Code's rule is
 * narrower: **no file write and no shell command executes without the user's
 * confirmation, unless the user added it to this session's allow-list.**
 *
 * - A configured `deny` still denies.
 * - A configured `allow` for a gated permission is read as `ask`: configuration
 *   cannot pre-approve a write or a command.
 * - Only a reply of "always" in *this* session allows a gated call without
 *   asking; it never carries to another session.
 * - Every other permission keeps upstream's evaluation.
 */
import type { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { Wildcard } from "@opencode-ai/core/util/wildcard"

/** The permissions a file write (`edit`, `write`, `apply_patch`) and a shell command request. */
export const GATED_PERMISSIONS: ReadonlySet<string> = new Set(["edit", "bash"])

function lastMatch(permission: string, pattern: string, rules: PermissionV1.Rule[]): PermissionV1.Rule | undefined {
  return rules.findLast((rule) => Wildcard.match(permission, rule.permission) && Wildcard.match(pattern, rule.pattern))
}

/**
 * The action for one (permission, pattern), given the configured ruleset and
 * the approvals this session has granted. Returns a rule; its `action` is what
 * `Permission.ask` acts on.
 */
export function decide(
  permission: string,
  pattern: string,
  ruleset: PermissionV1.Ruleset,
  sessionApproved: PermissionV1.Rule[],
): PermissionV1.Rule {
  const ask: PermissionV1.Rule = { action: "ask", permission, pattern: "*" }
  const configured = lastMatch(permission, pattern, [...ruleset])
  if (configured?.action === "deny") return configured
  const approved = lastMatch(permission, pattern, sessionApproved)
  if (approved?.action === "allow") return approved
  if (GATED_PERMISSIONS.has(permission)) return ask
  return configured ?? ask
}

export * as FloctaPolicy from "./policy"
