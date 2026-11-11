import {
  pgTable,
  uuid,
  text,
  integer,
  timestamp,
  jsonb,
  primaryKey,
  index,
  unique,
} from "drizzle-orm/pg-core";

export const events = pgTable(
  "events",
  {
    id: uuid("id").primaryKey(),
    ts: timestamp("ts", { withTimezone: true }).notNull(),
    source: text("source").notNull(),
    category: text("category").notNull(),
    action: text("action").notNull(),
    outcome: text("outcome").notNull(),
    severity: integer("severity").notNull(),
    actorUser: text("actor_user"),
    actorIp: text("actor_ip"),
    targetHost: text("target_host"),
    targetResource: text("target_resource"),
    targetIp: text("target_ip"),
    locationCountry: text("location_country"),
    locationCity: text("location_city"),
    raw: jsonb("raw").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    bySource: index("events_source_idx").on(t.source),
    byActorIp: index("events_actor_ip_idx").on(t.actorIp),
  }),
);

export const rules = pgTable("rules", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  severity: integer("severity").notNull(),
  definition: jsonb("definition").notNull(),
  enabled: integer("enabled").notNull().default(1),
});

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey(),
    eventId: uuid("event_id")
      .notNull()
      .references(() => events.id),
    ruleId: text("rule_id")
      .notNull()
      .references(() => rules.id),
    title: text("title").notNull(),
    severity: integer("severity").notNull(),
    ts: timestamp("ts", { withTimezone: true }).notNull(),
    actorIp: text("actor_ip"),
    actorUser: text("actor_user"),
    targetHost: text("target_host"),
    dedupeKey: text("dedupe_key").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    byDedupe: unique("alerts_dedupe_uniq").on(t.dedupeKey),
  }),
);

export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").primaryKey(),
    title: text("title").notNull(),
    status: text("status").notNull().default("open"),
    severity: integer("severity").notNull().default(0),
    correlationKey: text("correlation_key").notNull(),
    verdict: jsonb("verdict"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => ({
    byCorrelation: index("incidents_correlation_idx").on(t.correlationKey),
    byStatus: index("incidents_status_idx").on(t.status),
  }),
);

export const incidentAlerts = pgTable(
  "incident_alerts",
  {
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id),
    alertId: uuid("alert_id")
      .notNull()
      .references(() => alerts.id),
  },
  (t) => ({
    pk: primaryKey({ columns: [t.incidentId, t.alertId] }),
  }),
);

export const ledger = pgTable(
  "ledger",
  {
    id: uuid("id").primaryKey(),
    incidentId: uuid("incident_id")
      .notNull()
      .references(() => incidents.id),
    seq: integer("seq").notNull(),
    ts: timestamp("ts", { withTimezone: true }).notNull().defaultNow(),
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    detail: jsonb("detail").notNull(),
  },
  (t) => ({
    // One row per (incident, seq) — guarantees ordered, gap-checkable, append-only entries.
    uniqSeq: unique("ledger_incident_seq_uniq").on(t.incidentId, t.seq),
  }),
);

export const approvals = pgTable("approvals", {
  id: uuid("id").primaryKey(),
  incidentId: uuid("incident_id")
    .notNull()
    .references(() => incidents.id),
  decision: text("decision").notNull(),
  decidedBy: text("decided_by").notNull(),
  decidedAt: timestamp("decided_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  note: text("note"),
});
