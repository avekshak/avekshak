CREATE TABLE "alerts" (
	"id" uuid PRIMARY KEY NOT NULL,
	"event_id" uuid NOT NULL,
	"rule_id" text NOT NULL,
	"title" text NOT NULL,
	"severity" integer NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"actor_ip" text,
	"actor_user" text,
	"target_host" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "approvals" (
	"id" uuid PRIMARY KEY NOT NULL,
	"incident_id" uuid NOT NULL,
	"decision" text NOT NULL,
	"decided_by" text NOT NULL,
	"decided_at" timestamp with time zone NOT NULL,
	"note" text
);
--> statement-breakpoint
CREATE TABLE "events" (
	"id" uuid PRIMARY KEY NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"source" text NOT NULL,
	"category" text NOT NULL,
	"action" text NOT NULL,
	"outcome" text NOT NULL,
	"severity" integer NOT NULL,
	"actor_user" text,
	"actor_ip" text,
	"target_host" text,
	"target_resource" text,
	"target_ip" text,
	"location_country" text,
	"location_city" text,
	"raw" jsonb NOT NULL,
	"ingested_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incident_alerts" (
	"incident_id" uuid NOT NULL,
	"alert_id" uuid NOT NULL,
	"linked_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "incidents" (
	"id" uuid PRIMARY KEY NOT NULL,
	"title" text NOT NULL,
	"status" text DEFAULT 'open' NOT NULL,
	"severity" integer NOT NULL,
	"correlation_key" text NOT NULL,
	"verdict_verdict" text,
	"verdict_confidence" integer,
	"verdict_rationale" text,
	"verdict_recommended_action" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ledger" (
	"id" uuid PRIMARY KEY NOT NULL,
	"incident_id" uuid NOT NULL,
	"seq" integer NOT NULL,
	"ts" timestamp with time zone NOT NULL,
	"actor" text NOT NULL,
	"action" text NOT NULL,
	"detail" jsonb NOT NULL
);
--> statement-breakpoint
CREATE TABLE "rules" (
	"id" text PRIMARY KEY NOT NULL,
	"title" text NOT NULL,
	"description" text,
	"category" text NOT NULL,
	"severity" integer NOT NULL,
	"yaml" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_event_id_events_id_fk" FOREIGN KEY ("event_id") REFERENCES "public"."events"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_rule_id_rules_id_fk" FOREIGN KEY ("rule_id") REFERENCES "public"."rules"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "approvals" ADD CONSTRAINT "approvals_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD CONSTRAINT "incident_alerts_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "incident_alerts" ADD CONSTRAINT "incident_alerts_alert_id_alerts_id_fk" FOREIGN KEY ("alert_id") REFERENCES "public"."alerts"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ledger" ADD CONSTRAINT "ledger_incident_id_incidents_id_fk" FOREIGN KEY ("incident_id") REFERENCES "public"."incidents"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "alerts_event_id_idx" ON "alerts" USING btree ("event_id");--> statement-breakpoint
CREATE INDEX "alerts_ts_idx" ON "alerts" USING btree ("ts");--> statement-breakpoint
CREATE INDEX "alerts_actor_ip_idx" ON "alerts" USING btree ("actor_ip");--> statement-breakpoint
CREATE INDEX "events_ts_idx" ON "events" USING btree ("ts");--> statement-breakpoint
CREATE INDEX "events_actor_ip_idx" ON "events" USING btree ("actor_ip");--> statement-breakpoint
CREATE INDEX "events_source_idx" ON "events" USING btree ("source");--> statement-breakpoint
CREATE INDEX "incident_alerts_incident_idx" ON "incident_alerts" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "incident_alerts_alert_idx" ON "incident_alerts" USING btree ("alert_id");--> statement-breakpoint
CREATE INDEX "incidents_status_idx" ON "incidents" USING btree ("status");--> statement-breakpoint
CREATE INDEX "incidents_correlation_key_idx" ON "incidents" USING btree ("correlation_key");--> statement-breakpoint
CREATE INDEX "incidents_severity_idx" ON "incidents" USING btree ("severity");--> statement-breakpoint
CREATE INDEX "ledger_incident_id_idx" ON "ledger" USING btree ("incident_id");--> statement-breakpoint
CREATE INDEX "ledger_seq_idx" ON "ledger" USING btree ("incident_id","seq");