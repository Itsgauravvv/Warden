CREATE TABLE `api_keys` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`project_id` text,
	`name` text NOT NULL,
	`prefix` text NOT NULL,
	`key_hash` text NOT NULL,
	`scopes_json` text NOT NULL,
	`expires_at` integer,
	`revoked_at` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`project_id`) REFERENCES `projects`(`id`) ON UPDATE no action ON DELETE set null
);
--> statement-breakpoint
CREATE UNIQUE INDEX `api_keys_key_hash_unique` ON `api_keys` (`key_hash`);--> statement-breakpoint
CREATE INDEX `idx_api_keys_tenant` ON `api_keys` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `approvals` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`tool_call_id` text NOT NULL,
	`status` text NOT NULL,
	`decided_by` text,
	`reason` text,
	`expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`tool_call_id`) REFERENCES `tool_calls`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_approvals_tenant_status` ON `approvals` (`tenant_id`,`status`);--> statement-breakpoint
CREATE TABLE `audit_batches` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`first_seq` integer NOT NULL,
	`last_seq` integer NOT NULL,
	`root_hash` text NOT NULL,
	`signature` text NOT NULL,
	`r2_archive_key` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_audit_batches_tenant` ON `audit_batches` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `audit_records` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`seq` integer NOT NULL,
	`request_id` text,
	`event_type` text NOT NULL,
	`canonical_json` text NOT NULL,
	`prev_hash` text NOT NULL,
	`record_hash` text NOT NULL,
	`batch_id` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_audit_records_tenant_seq` ON `audit_records` (`tenant_id`,`seq`);--> statement-breakpoint
CREATE TABLE `budgets` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`scope` text NOT NULL,
	`scope_id` text NOT NULL,
	`rpm_limit` integer DEFAULT 60 NOT NULL,
	`daily_token_limit` integer DEFAULT 500000 NOT NULL,
	`monthly_cost_limit_usd` real DEFAULT 10 NOT NULL,
	`judge_daily_budget_usd` real DEFAULT 1 NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_budgets_tenant_scope` ON `budgets` (`tenant_id`,`scope`,`scope_id`);--> statement-breakpoint
CREATE TABLE `eval_cases` (
	`id` text PRIMARY KEY NOT NULL,
	`eval_run_id` text NOT NULL,
	`case_id` text NOT NULL,
	`expected_malicious` integer NOT NULL,
	`actual_blocked` integer NOT NULL,
	`latency_ms` integer NOT NULL,
	FOREIGN KEY (`eval_run_id`) REFERENCES `eval_runs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE TABLE `eval_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`git_commit` text NOT NULL,
	`tpr` real NOT NULL,
	`fpr` real NOT NULL,
	`metrics_by_detector_json` text NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`request_id` text NOT NULL,
	`detector` text NOT NULL,
	`rule_id` text NOT NULL,
	`owasp_category` text NOT NULL,
	`confidence` real NOT NULL,
	`action` text NOT NULL,
	`direction` text NOT NULL,
	`evidence_start` integer NOT NULL,
	`evidence_end` integer NOT NULL,
	`snippet_redacted` text NOT NULL,
	`message` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`request_id`) REFERENCES `requests`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_findings_tenant_req` ON `findings` (`tenant_id`,`request_id`);--> statement-breakpoint
CREATE TABLE `memberships` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`user_id` text NOT NULL,
	`role` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_memberships_tenant_user` ON `memberships` (`tenant_id`,`user_id`);--> statement-breakpoint
CREATE TABLE `policies` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`name` text NOT NULL,
	`current_version_id` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_policies_tenant` ON `policies` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `policy_versions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`policy_id` text NOT NULL,
	`version_number` integer NOT NULL,
	`yaml_content` text NOT NULL,
	`parsed_json` text NOT NULL,
	`created_by` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`policy_id`) REFERENCES `policies`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_policy_versions_tenant_policy` ON `policy_versions` (`tenant_id`,`policy_id`);--> statement-breakpoint
CREATE TABLE `projects` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`name` text NOT NULL,
	`active_policy_id` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_projects_tenant` ON `projects` (`tenant_id`);--> statement-breakpoint
CREATE TABLE `provider_credentials` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`provider` text NOT NULL,
	`base_url` text,
	`encrypted_api_key` text NOT NULL,
	`iv` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_provider_creds_tenant` ON `provider_credentials` (`tenant_id`,`provider`);--> statement-breakpoint
CREATE TABLE `redteam_attacks` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`run_id` text NOT NULL,
	`category` text NOT NULL,
	`round` integer NOT NULL,
	`prompt_payload` text NOT NULL,
	`blocked` integer NOT NULL,
	`finding_ids_json` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`run_id`) REFERENCES `redteam_runs`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_redteam_attacks_tenant_run` ON `redteam_attacks` (`tenant_id`,`run_id`);--> statement-breakpoint
CREATE TABLE `redteam_runs` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`policy_id` text NOT NULL,
	`total_attacks` integer NOT NULL,
	`blocked_attacks` integer NOT NULL,
	`leaked_attacks` integer NOT NULL,
	`suggested_patch_yaml` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_redteam_runs_tenant` ON `redteam_runs` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `requests` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`project_id` text,
	`session_id` text,
	`provider` text NOT NULL,
	`model` text NOT NULL,
	`final_action` text NOT NULL,
	`cache_hit` integer DEFAULT false NOT NULL,
	`prompt_tokens` integer DEFAULT 0 NOT NULL,
	`completion_tokens` integer DEFAULT 0 NOT NULL,
	`cost_usd` real DEFAULT 0 NOT NULL,
	`latency_ms` integer DEFAULT 0 NOT NULL,
	`prompt_redacted` text NOT NULL,
	`response_redacted` text,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_requests_tenant_time` ON `requests` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`project_id` text,
	`tainted` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_sessions_tenant_time` ON `sessions` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `tenants` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`slug` text NOT NULL,
	`is_sandbox` integer DEFAULT false NOT NULL,
	`retention_days` integer DEFAULT 30 NOT NULL,
	`raw_payload_opt_in` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `tenants_slug_unique` ON `tenants` (`slug`);--> statement-breakpoint
CREATE TABLE `tool_calls` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`request_id` text NOT NULL,
	`session_id` text,
	`tool_name` text NOT NULL,
	`arguments_redacted_json` text NOT NULL,
	`taint_detected` integer DEFAULT false NOT NULL,
	`status` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`request_id`) REFERENCES `requests`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_tool_calls_tenant_time` ON `tool_calls` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`github_id` text NOT NULL,
	`email` text NOT NULL,
	`name` text NOT NULL,
	`avatar_url` text,
	`created_at` integer NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_github_id_unique` ON `users` (`github_id`);--> statement-breakpoint
CREATE TABLE `webhook_deliveries` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`webhook_id` text NOT NULL,
	`idempotency_key` text NOT NULL,
	`status` text NOT NULL,
	`attempts` integer DEFAULT 0 NOT NULL,
	`last_status_code` integer,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`webhook_id`) REFERENCES `webhooks`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `webhook_deliveries_idempotency_key_unique` ON `webhook_deliveries` (`idempotency_key`);--> statement-breakpoint
CREATE INDEX `idx_webhook_deliveries_tenant` ON `webhook_deliveries` (`tenant_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `webhooks` (
	`id` text PRIMARY KEY NOT NULL,
	`tenant_id` text NOT NULL,
	`url` text NOT NULL,
	`signing_secret_encrypted` text NOT NULL,
	`events_json` text NOT NULL,
	`active` integer DEFAULT true NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`tenant_id`) REFERENCES `tenants`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `idx_webhooks_tenant` ON `webhooks` (`tenant_id`);