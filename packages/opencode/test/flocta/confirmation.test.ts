/**
 * Flocta AC 10.1.3 (ADR 0042 §3.5, D-341): no file write or shell command
 * executes without the user's confirmation unless it is on the session's
 * allow-list. The AC names one test in particular — decline a write and assert
 * the file is unchanged — which is the last one here, through the real write
 * tool and the real permission service.
 */
import { afterEach, describe, expect, test } from "bun:test"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { LayerNode } from "@opencode-ai/core/effect/layer-node"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { Cause, Effect, Exit, Fiber } from "effect"
import fs from "fs/promises"
import path from "path"
import { FloctaPolicy } from "../../src/flocta/policy"
import { Permission } from "../../src/permission"
import { EventV2Bridge } from "../../src/event-v2-bridge"
import { WriteTool } from "../../src/tool/write"
import { LSP } from "@/lsp/lsp"
import { Format } from "../../src/format"
import { Truncate } from "@/tool/truncate"
import { Agent } from "../../src/agent/agent"
import { MessageID, SessionID } from "../../src/session/schema"
import { disposeAllInstances, TestInstance } from "../fixture/fixture"
import { testEffect } from "../lib/effect"

const ALLOW_ALL: PermissionV1.Rule[] = [{ permission: "*", pattern: "*", action: "allow" }]

afterEach(async () => {
  await disposeAllInstances()
})

describe("FloctaPolicy.decide", () => {
  test("a configured allow does not pre-approve a write or a command", () => {
    for (const permission of ["edit", "bash"]) {
      expect(FloctaPolicy.decide(permission, "*", ALLOW_ALL, []).action).toBe("ask")
      const specific: PermissionV1.Rule[] = [{ permission, pattern: "*", action: "allow" }]
      expect(FloctaPolicy.decide(permission, "ls", specific, []).action).toBe("ask")
    }
  })

  test("a configured deny still denies", () => {
    const deny: PermissionV1.Rule[] = [{ permission: "bash", pattern: "rm *", action: "deny" }]
    expect(FloctaPolicy.decide("bash", "rm -rf /", deny, []).action).toBe("deny")
  })

  test("a deny outranks even this session's approval", () => {
    const deny: PermissionV1.Rule[] = [{ permission: "bash", pattern: "rm *", action: "deny" }]
    const approved: PermissionV1.Rule[] = [{ permission: "bash", pattern: "*", action: "allow" }]
    expect(FloctaPolicy.decide("bash", "rm -rf /", deny, approved).action).toBe("deny")
  })

  test("this session's approval allows the gated call", () => {
    const approved: PermissionV1.Rule[] = [{ permission: "bash", pattern: "ls", action: "allow" }]
    expect(FloctaPolicy.decide("bash", "ls", ALLOW_ALL, approved).action).toBe("allow")
    expect(FloctaPolicy.decide("bash", "pwd", ALLOW_ALL, approved).action).toBe("ask")
  })

  test("permissions the policy does not gate keep upstream's evaluation", () => {
    expect(FloctaPolicy.decide("read", "src/a.ts", ALLOW_ALL, []).action).toBe("allow")
    expect(FloctaPolicy.decide("read", "src/a.ts", [], []).action).toBe("ask")
  })

  test("the gated set is exactly writes and commands", () => {
    expect([...FloctaPolicy.GATED_PERMISSIONS].sort()).toEqual(["bash", "edit"])
  })
})

const it = testEffect(
  LayerNode.compile(
    LayerNode.group([
      LSP.node,
      FSUtil.node,
      EventV2Bridge.node,
      Format.node,
      CrossSpawnSpawner.node,
      Truncate.node,
      Agent.node,
      Permission.node,
    ]),
  ),
)

const waitForPending = (count: number) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    while (true) {
      const list = yield* permission.list()
      if (list.length === count) return list
      yield* Effect.sleep("10 millis")
    }
  }).pipe(
    Effect.timeoutOrElse({
      duration: "2 seconds",
      orElse: () => Effect.fail(new Error(`timed out waiting for ${count} pending request(s)`)),
    }),
  )

const reply = (requestID: PermissionV1.ID, answer: "once" | "always" | "reject") =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    yield* permission.reply({ requestID, reply: answer })
  })

const askBash = (session: string, id: string, pattern = "ls") =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    return yield* permission.ask({
      id: PermissionV1.ID.make(id),
      sessionID: SessionID.make(session),
      permission: "bash",
      patterns: [pattern],
      metadata: {},
      always: [pattern],
      ruleset: ALLOW_ALL,
    })
  })

describe("the permission service under the Flocta policy", () => {
  it.instance("a command asks even when the configuration allows everything", () =>
    Effect.gen(function* () {
      const fiber = yield* askBash("ses_flocta_a", "per_flocta_1").pipe(Effect.forkScoped)
      const [pending] = yield* waitForPending(1)
      expect(pending.permission).toBe("bash")
      yield* reply(PermissionV1.ID.make("per_flocta_1"), "once")
      yield* Fiber.join(fiber)
    }),
  )

  it.instance("once allows that call only; the next one asks again", () =>
    Effect.gen(function* () {
      const first = yield* askBash("ses_flocta_b", "per_flocta_2").pipe(Effect.forkScoped)
      yield* waitForPending(1)
      yield* reply(PermissionV1.ID.make("per_flocta_2"), "once")
      yield* Fiber.join(first)

      const second = yield* askBash("ses_flocta_b", "per_flocta_3").pipe(Effect.forkScoped)
      yield* waitForPending(1)
      yield* reply(PermissionV1.ID.make("per_flocta_3"), "reject")
      const exit = yield* Fiber.await(second)
      expect(Exit.isFailure(exit)).toBe(true)
    }),
  )

  it.instance("always adds to this session's allow-list and no other session's", () =>
    Effect.gen(function* () {
      const first = yield* askBash("ses_flocta_c", "per_flocta_4").pipe(Effect.forkScoped)
      yield* waitForPending(1)
      yield* reply(PermissionV1.ID.make("per_flocta_4"), "always")
      yield* Fiber.join(first)

      // Same session, same command: on the allow-list, no prompt.
      yield* askBash("ses_flocta_c", "per_flocta_5")

      // Another session: asks.
      const other = yield* askBash("ses_flocta_d", "per_flocta_6").pipe(Effect.forkScoped)
      const [pending] = yield* waitForPending(1)
      expect(pending.sessionID).toBe(SessionID.make("ses_flocta_d"))
      yield* reply(PermissionV1.ID.make("per_flocta_6"), "reject")
      expect(Exit.isFailure(yield* Fiber.await(other))).toBe(true)
    }),
  )

  it.instance("a declined write leaves the file unchanged", () =>
    Effect.gen(function* () {
      const instance = yield* TestInstance
      const target = path.join(instance.directory, "keep.txt")
      yield* Effect.promise(() => fs.writeFile(target, "original contents\n"))

      const permission = yield* Permission.Service
      // The real `build` agent's ruleset — upstream's default, which allows everything.
      const build = yield* (yield* Agent.Service).get("build")
      const sessionID = SessionID.make("ses_flocta_write")
      const tool = yield* (yield* WriteTool).init()
      const run = tool
        .execute(
          { filePath: target, content: "overwritten by the model\n" },
          {
            sessionID,
            messageID: MessageID.make("msg_flocta_write"),
            callID: "",
            agent: "build",
            abort: AbortSignal.any([]),
            messages: [],
            metadata: () => Effect.void,
            // As `session/tools.ts` wires it: the agent's ruleset, and `orDie`.
            ask: (request) =>
              permission.ask({ ...request, sessionID, ruleset: build.permission }).pipe(Effect.orDie),
          },
        )
        .pipe(Effect.forkScoped)

      const fiber = yield* run
      const [pending] = yield* waitForPending(1)
      expect(pending.permission).toBe("edit")
      yield* permission.reply({ requestID: pending.id, reply: "reject" })
      const exit = yield* Fiber.await(fiber)

      expect(Exit.isFailure(exit)).toBe(true)
      if (Exit.isFailure(exit)) expect(String(Cause.squash(exit.cause))).not.toContain("Wrote file")
      const after = yield* Effect.promise(() => fs.readFile(target, "utf-8"))
      expect(after).toBe("original contents\n")
    }),
  )
})
