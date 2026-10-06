/**
 * The event queue. EventQueue is the interface; InProcessQueue is the v1
 * implementation, small enough for one site or a handful. A real broker can
 * replace it later without touching a worker or the orchestrator.
 *
 * Guarantees, and where they stop:
 *  - Every event is validated against the schema before anything sees it.
 *    Invalid events never reach a subscriber; they are journaled as rejected.
 *  - An accepted event is written to the journal BEFORE delivery, so the audit
 *    trail holds everything the orchestrator was ever shown.
 *  - Delivery is in publish order, one event at a time. One failing subscriber
 *    does not stop the others and is recorded, not swallowed.
 *  - Not guaranteed: if the process dies between journaling and delivery, that
 *    event is not redelivered on restart. Workers compare against a baseline
 *    on every pass, so a real condition is detected again.
 */

import { SecurityEvent } from "./events.js";
import type { Journal } from "./journal.js";

export type EventHandler = (event: SecurityEvent) => void | Promise<void>;
export type PublishResult = { ok: true; event: SecurityEvent } | { ok: false; error: string };

export interface EventQueue {
  publish(raw: unknown): Promise<PublishResult>;
  subscribe(handler: EventHandler): () => void;
  /** Resolves when everything published so far has been delivered. */
  drain(): Promise<void>;
  close(): Promise<void>;
}

const SEEN_LIMIT = 10_000;

function snippet(raw: unknown): string {
  try {
    return (JSON.stringify(raw) ?? String(raw)).slice(0, 2000);
  } catch {
    return "(unserialisable)";
  }
}

export class InProcessQueue implements EventQueue {
  private handlers: EventHandler[] = [];
  private delivery: Promise<void> = Promise.resolve();
  private closed = false;
  private seen = new Set<string>();

  constructor(
    private readonly journal: Journal,
    private readonly onError: (message: string) => void = () => undefined,
  ) {}

  subscribe(handler: EventHandler): () => void {
    this.handlers.push(handler);
    return () => {
      this.handlers = this.handlers.filter((h) => h !== handler);
    };
  }

  async publish(raw: unknown): Promise<PublishResult> {
    if (this.closed) return { ok: false, error: "queue is closed" };

    const parsed = SecurityEvent.safeParse(raw);
    if (!parsed.success) {
      const issues = parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
      await this.journal.append("event_rejected", { issues, raw: snippet(raw) });
      return { ok: false, error: issues.join("; ") };
    }

    const event = parsed.data;
    if (this.seen.has(event.id)) {
      await this.journal.append("event_rejected", { issues: ["duplicate event id"], raw: snippet({ id: event.id }) });
      return { ok: false, error: "duplicate event id" };
    }
    this.seen.add(event.id);
    if (this.seen.size > SEEN_LIMIT) this.seen.delete(this.seen.values().next().value as string);

    await this.journal.append("event", event);
    this.delivery = this.delivery.then(() => this.deliver(event));
    return { ok: true, event };
  }

  private async deliver(event: SecurityEvent): Promise<void> {
    for (const handler of [...this.handlers]) {
      try {
        await handler(event);
      } catch (e: any) {
        const message = String(e?.message ?? e).slice(0, 300);
        this.onError(`subscriber failed on ${event.id}: ${message}`);
        await this.journal.append("handler_error", { eventId: event.id, message }).catch(() => undefined);
      }
    }
  }

  async drain(): Promise<void> {
    let d: Promise<void>;
    do {
      d = this.delivery;
      await d;
    } while (d !== this.delivery);
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.drain();
  }
}
