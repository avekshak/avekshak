import { pgTable, uuid, text, integer, timestamp, jsonb, index, primaryKey } from "drizzle-orm/pg-core";

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
    ingestedAt: timestamp("ingested_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    index("events_ts_idx").on(t.ts),
    index("events_actor_ip_idx").on(t.actorIp),
    index("events_source_idx").on(t.source),
  ],
);

export const rules = pgTable("rules", {
  id: text("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description"),
  category: text("category").notNull(),
  severity: integer("severity").notNull(),
  yaml: text("yaml").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const alerts = pgTable(
  "alerts",
  {
    id: uuid("id").primaryKey(),
    eventId: uuid("event_id").notNull().references(() => events.id),
    ruleId: text("rule_id").notNull().references(() => rules.id),
    title: text("title").notNull(),
    severity: integer("severity").notNull(),
    ts: timestamp("ts", { withTimezone: true }).notNull(),
    actorIp: text("actor_ip"),
    actorUser: text("actor_user"),
    targetHost: text("target_host"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    index("alerts_event_id_idx").on(t.eventId),
    index("alerts_ts_idx").on(t.ts),
    index("alerts_actor_ip_idx").on(t.actorIp),
  ],
);

export const incidents = pgTable(
  "incidents",
  {
    id: uuid("id").primaryKey(),
    title: text("title").notNull(),
    status: text("status").notNull().default("open"),
    severity: integer("severity").notNull(),
    correlationKey: text("correlation_key").notNull(),
    verdictVerdict: text("verdict_verdict"),
    verdictConfidence: integer("verdict_confidence"),
    verdictRationale: text("verdict_rationale"),
    verdictRecommendedAction: text("verdict_recommended_action"),
    createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    index("incidents_status_idx").on(t.status),
    index("incidents_correlation_key_idx").on(t.correlationKey),
    index("incidents_severity_idx").on(t.severity),
  ],
);

export const incidentAlerts = pgTable(
  "incident_alerts",
  {
    incidentId: uuid("incident_id").notNull().references(() => incidents.id),
    alertId: uuid("alert_id").notNull().references(() => alerts.id),
    linkedAt: timestamp("linked_at", { withTimezone: true }).defaultNow().notNull(),
  },
  (t) => [
    primaryKey({ columns: [t.incidentId, t.alertId] }),
    index("incident_alerts_incident_idx").on(t.incidentId),
    index("incident_alerts_alert_idx").on(t.alertId),
  ],
);

export const ledger = pgTable(
  "ledger",
  {
    id: uuid("id").primaryKey(),
    incidentId: uuid("incident_id").notNull().references(() => incidents.id),
    seq: integer("seq").notNull(),
    ts: timestamp("ts", { withTimezone: true }).notNull(),
    actor: text("actor").notNull(),
    action: text("action").notNull(),
    detail: jsonb("detail").notNull(),
  },
  (t) => [
    index("ledger_incident_id_idx").on(t.incidentId),
    index("ledger_seq_idx").on(t.incidentId, t.seq),
  ],
);

export const approvals = pgTable("approvals", {
  id: uuid("id").primaryKey(),
  incidentId: uuid("incident_id").notNull().references(() => incidents.id),
  decision: text("decision").notNull(),
  decidedBy: text("decided_by").notNull(),
  decidedAt: timestamp("decided_at", { withTimezone: true }).notNull(),
  note: text("note"),
});
