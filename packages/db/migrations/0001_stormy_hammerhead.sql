DROP INDEX IF EXISTS "alerts_dedupe_idx";--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_dedupe_uniq" UNIQUE("dedupe_key");