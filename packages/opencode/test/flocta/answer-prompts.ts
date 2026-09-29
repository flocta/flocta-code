/**
 * Flocta AC 10.1.3: a write or a command now asks even where a test's session
 * or config allows everything. Tests that exercise a tool's *execution* — not
 * its confirmation — answer each prompt of their session the way a person
 * would, "once", so the tool runs and nothing is added to the allow-list.
 */
import { Effect } from "effect"
import { Permission } from "../../src/permission"
import type { SessionID } from "../../src/session/schema"

export const answerPrompts = (sessionID: SessionID) =>
  Effect.gen(function* () {
    const permission = yield* Permission.Service
    while (true) {
      for (const request of yield* permission.list()) {
        if (request.sessionID !== sessionID) continue
        yield* permission.reply({ requestID: request.id, reply: "once" }).pipe(Effect.ignore)
      }
      yield* Effect.sleep("10 millis")
    }
  })
