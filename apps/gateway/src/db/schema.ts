import { sqliteTable, text, integer, real, index, uniqueIndex } from "drizzle-orm/sqlite-core";

// 1. Tenants
export const tenants = sqliteTable("tenants", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  slug: text("slug").notNull().unique(),
  isSandbox: integer("is_sandbox", { mode: "boolean" }).notNull().default(false),
  retentionDays: integer("retention_days").notNull().default(30),
  rawPayloadOptIn: integer("raw_payload_opt_in", { mode: "boolean" }).notNull().default(false),
  createdAt: integer("created_at").notNull(),
});

// 2. Users (GitHub OAuth)
export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  githubId: text("github_id").notNull().unique(),
  email: text("email").notNull(),
  name: text("name").notNull(),
  avatarUrl: text("avatar_url"),
  createdAt: integer("created_at").notNull(),
});

// 3. Memberships (RBAC: owner, admin, viewer)
export const memberships = sqliteTable(
  "memberships",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    role: text("role", { enum: ["owner", "admin", "viewer"] }).notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [uniqueIndex("idx_memberships_tenant_user").on(t.tenantId, t.userId)]
);

// 4. Projects
export const projects = sqliteTable(
  "projects",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    activePolicyId: text("active_policy_id"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_projects_tenant").on(t.tenantId)]
);

// 5. API Keys (stored ONLY as SHA-256 hash, shown once)
export const apiKeys = sqliteTable(
  "api_keys",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    projectId: text("project_id").references(() => projects.id, { onDelete: "set null" }),
    name: text("name").notNull(),
    prefix: text("prefix").notNull(),
    keyHash: text("key_hash").notNull().unique(),
    scopesJson: text("scopes_json").notNull(), // e.g. '["proxy:write","admin:read"]'
    expiresAt: integer("expires_at"),
    revokedAt: integer("revoked_at"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_api_keys_tenant").on(t.tenantId)]
);

// 6. Provider Credentials (AES-GCM encrypted at rest; default provider: gemini)
export const providerCredentials = sqliteTable(
  "provider_credentials",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    provider: text("provider", { enum: ["gemini", "groq", "openrouter", "workers_ai", "openai_compatible"] }).notNull(),
    baseUrl: text("base_url"),
    encryptedApiKey: text("encrypted_api_key").notNull(),
    iv: text("iv").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_provider_creds_tenant").on(t.tenantId, t.provider)]
);

// 7. Policies
export const policies = sqliteTable(
  "policies",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    currentVersionId: text("current_version_id"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_policies_tenant").on(t.tenantId)]
);

// 8. Policy Versions (immutable snapshots for instant rollback & diffs)
export const policyVersions = sqliteTable(
  "policy_versions",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    policyId: text("policy_id").notNull().references(() => policies.id, { onDelete: "cascade" }),
    versionNumber: integer("version_number").notNull(),
    yamlContent: text("yaml_content").notNull(),
    parsedJson: text("parsed_json").notNull(),
    createdBy: text("created_by"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_policy_versions_tenant_policy").on(t.tenantId, t.policyId)]
);

// 9. Sessions (Agent conversation graphs)
export const sessions = sqliteTable(
  "sessions",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    projectId: text("project_id"),
    tainted: integer("tainted", { mode: "boolean" }).notNull().default(false),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_sessions_tenant_time").on(t.tenantId, t.createdAt)]
);

// 10. Requests
export const requests = sqliteTable(
  "requests",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    projectId: text("project_id"),
    sessionId: text("session_id"),
    provider: text("provider").notNull(),
    model: text("model").notNull(),
    finalAction: text("final_action", { enum: ["allow", "redact", "block", "flag", "shadow"] }).notNull(),
    cacheHit: integer("cache_hit", { mode: "boolean" }).notNull().default(false),
    promptTokens: integer("prompt_tokens").notNull().default(0),
    completionTokens: integer("completion_tokens").notNull().default(0),
    costUsd: real("cost_usd").notNull().default(0),
    latencyMs: integer("latency_ms").notNull().default(0),
    promptRedacted: text("prompt_redacted").notNull(),
    responseRedacted: text("response_redacted"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_requests_tenant_time").on(t.tenantId, t.createdAt)]
);

// 11. Findings
export const findings = sqliteTable(
  "findings",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    requestId: text("request_id").notNull().references(() => requests.id, { onDelete: "cascade" }),
    detector: text("detector").notNull(),
    ruleId: text("rule_id").notNull(),
    owaspCategory: text("owasp_category").notNull(),
    confidence: real("confidence").notNull(),
    action: text("action").notNull(),
    direction: text("direction").notNull(),
    evidenceStart: integer("evidence_start").notNull(),
    evidenceEnd: integer("evidence_end").notNull(),
    snippetRedacted: text("snippet_redacted").notNull(),
    message: text("message").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_findings_tenant_req").on(t.tenantId, t.requestId)]
);

// 12. Tool Calls (Agent Firewall)
export const toolCalls = sqliteTable(
  "tool_calls",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    requestId: text("request_id").notNull().references(() => requests.id, { onDelete: "cascade" }),
    sessionId: text("session_id"),
    toolName: text("tool_name").notNull(),
    argumentsRedactedJson: text("arguments_redacted_json").notNull(),
    taintDetected: integer("taint_detected", { mode: "boolean" }).notNull().default(false),
    status: text("status", { enum: ["allowed", "blocked", "pending_approval", "approved", "denied"] }).notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_tool_calls_tenant_time").on(t.tenantId, t.createdAt)]
);

// 13. Approvals Queue (Human-in-the-loop for high-risk agent tool calls)
export const approvals = sqliteTable(
  "approvals",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    toolCallId: text("tool_call_id").notNull().references(() => toolCalls.id, { onDelete: "cascade" }),
    status: text("status", { enum: ["pending", "approved", "rejected", "expired"] }).notNull(),
    decidedBy: text("decided_by"),
    reason: text("reason"),
    expiresAt: integer("expires_at").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_approvals_tenant_status").on(t.tenantId, t.status)]
);

// 14. Audit Batches (Sealed & signed hash-chain batches)
export const auditBatches = sqliteTable(
  "audit_batches",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    firstSeq: integer("first_seq").notNull(),
    lastSeq: integer("last_seq").notNull(),
    rootHash: text("root_hash").notNull(),
    signature: text("signature").notNull(),
    r2ArchiveKey: text("r2_archive_key"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_audit_batches_tenant").on(t.tenantId, t.createdAt)]
);

// 15. Audit Records (Tamper-evident SHA-256 chain)
export const auditRecords = sqliteTable(
  "audit_records",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    seq: integer("seq").notNull(),
    requestId: text("request_id"),
    eventType: text("event_type").notNull(),
    canonicalJson: text("canonical_json").notNull(),
    prevHash: text("prev_hash").notNull(),
    recordHash: text("record_hash").notNull(),
    batchId: text("batch_id"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [uniqueIndex("idx_audit_records_tenant_seq").on(t.tenantId, t.seq)]
);

// 16. Budgets & Rate Limit Configs
export const budgets = sqliteTable(
  "budgets",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    scope: text("scope", { enum: ["tenant", "project", "key"] }).notNull(),
    scopeId: text("scope_id").notNull(),
    rpmLimit: integer("rpm_limit").notNull().default(60),
    dailyTokenLimit: integer("daily_token_limit").notNull().default(500000),
    monthlyCostLimitUsd: real("monthly_cost_limit_usd").notNull().default(10.0),
    judgeDailyBudgetUsd: real("judge_daily_budget_usd").notNull().default(1.0),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_budgets_tenant_scope").on(t.tenantId, t.scope, t.scopeId)]
);

// 17. Webhooks
export const webhooks = sqliteTable(
  "webhooks",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    url: text("url").notNull(),
    signingSecretEncrypted: text("signing_secret_encrypted").notNull(),
    eventsJson: text("events_json").notNull(),
    active: integer("active", { mode: "boolean" }).notNull().default(true),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_webhooks_tenant").on(t.tenantId)]
);

// 18. Webhook Deliveries (Idempotent retries + DLQ tracking)
export const webhookDeliveries = sqliteTable(
  "webhook_deliveries",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    webhookId: text("webhook_id").notNull().references(() => webhooks.id, { onDelete: "cascade" }),
    idempotencyKey: text("idempotency_key").notNull().unique(),
    status: text("status", { enum: ["pending", "delivered", "failed", "dlq"] }).notNull(),
    attempts: integer("attempts").notNull().default(0),
    lastStatusCode: integer("last_status_code"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_webhook_deliveries_tenant").on(t.tenantId, t.createdAt)]
);

// 19. Eval Runs & Eval Cases
export const evalRuns = sqliteTable("eval_runs", {
  id: text("id").primaryKey(),
  gitCommit: text("git_commit").notNull(),
  tpr: real("tpr").notNull(),
  fpr: real("fpr").notNull(),
  metricsByDetectorJson: text("metrics_by_detector_json").notNull(),
  createdAt: integer("created_at").notNull(),
});

export const evalCases = sqliteTable("eval_cases", {
  id: text("id").primaryKey(),
  evalRunId: text("eval_run_id").notNull().references(() => evalRuns.id, { onDelete: "cascade" }),
  caseId: text("case_id").notNull(),
  expectedMalicious: integer("expected_malicious", { mode: "boolean" }).notNull(),
  actualBlocked: integer("actual_blocked", { mode: "boolean" }).notNull(),
  latencyMs: integer("latency_ms").notNull(),
});

// 20. Red-Team Runs & Red-Team Attacks ("Imp")
export const redteamRuns = sqliteTable(
  "redteam_runs",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    policyId: text("policy_id").notNull(),
    totalAttacks: integer("total_attacks").notNull(),
    blockedAttacks: integer("blocked_attacks").notNull(),
    leakedAttacks: integer("leaked_attacks").notNull(),
    suggestedPatchYaml: text("suggested_patch_yaml"),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_redteam_runs_tenant").on(t.tenantId, t.createdAt)]
);

export const redteamAttacks = sqliteTable(
  "redteam_attacks",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().references(() => tenants.id, { onDelete: "cascade" }),
    runId: text("run_id").notNull().references(() => redteamRuns.id, { onDelete: "cascade" }),
    category: text("category").notNull(),
    round: integer("round").notNull(),
    promptPayload: text("prompt_payload").notNull(),
    blocked: integer("blocked", { mode: "boolean" }).notNull(),
    findingIdsJson: text("finding_ids_json").notNull(),
    createdAt: integer("created_at").notNull(),
  },
  (t) => [index("idx_redteam_attacks_tenant_run").on(t.tenantId, t.runId)]
);