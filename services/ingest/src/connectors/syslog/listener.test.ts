import { describe, it, expect, vi } from "vitest";
import type { TypedQueue } from "@avekshak/queue";
import type { NormalizedEvent } from "@avekshak/schema";
import { handleSyslogLine } from "./listener.js";

function fakeQueue() {
  const enqueued: NormalizedEvent[] = [];
  const queue: TypedQueue<NormalizedEvent> = {
    enqueue: async (_name, data) => {
      enqueued.push(data);
      return { data } as never;
    },
    close: async () => {},
  };
  return { queue, enqueued };
}

describe("handleSyslogLine", () => {
  it("enqueues a normalized event for a valid line", async () => {
    const { queue, enqueued } = fakeQueue();
    const ok = await handleSyslogLine(
      "<38>Nov 10 02:00:00 webhost sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
      queue,
    );
    expect(ok).toBe(true);
    expect(enqueued).toHaveLength(1);
    expect(enqueued[0].action).toBe("login_failed");
    expect(enqueued[0].actor.ip).toBe("203.0.113.9");
  });

  it("skips a malformed line and calls onSkip without enqueuing", async () => {
    const { queue, enqueued } = fakeQueue();
    const onSkip = vi.fn();
    const ok = await handleSyslogLine("   ", queue, onSkip);
    expect(ok).toBe(false);
    expect(enqueued).toHaveLength(0);
    expect(onSkip).toHaveBeenCalledOnce();
  });
});
