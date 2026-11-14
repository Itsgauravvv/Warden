import { and, desc, eq } from "drizzle-orm";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "./schema.js";
import { generateTenantApiKey, sha256Hex, type ApiKeyScope } from "../auth/api-key.js";
import { decryptSecret, encryptSecret } from "../crypto/aes-gcm.js";
import type { ProviderName } from "../adapters/provider.js";

export type WardenDb = BaseSQLiteDatabase<"sync" | "async", unknown, typeof schema>;

export class TenantRepository {
  constructor(
    private readonly db: WardenDb,
    private readonly encryptionSecret = "warden-local-dev-master-secret-32b!"
  ) {}

  async createTenant(input: { id: string; name: string; slug: string; isSandbox?: boolean }) {
    const now = Date.now();
    await this.db.insert(schema.tenants).values({
      id: input.id,
      name: input.name,
      slug: input.slug,
      isSandbox: input.isSandbox ?? false,
      createdAt: now,
    });
  }

  async createApiKey(input: {
    id: string;
    tenantId: string;
    name: string;
    scopes: ApiKeyScope[];
    isSandbox?: boolean;
    expiresAt?: number;
  }) {
    const generated = await generateTenantApiKey(input.isSandbox);
    await this.db.insert(schema.apiKeys).values({
      id: input.id,
      tenantId: input.tenantId,
      name: input.name,
      prefix: generated.prefix,
      keyHash: generated.keyHash,
      scopesJson: JSON.stringify(input.scopes),
      expiresAt: input.expiresAt ?? null,
      createdAt: Date.now(),
    });

    return {
      id: input.id,
      tenantId: input.tenantId,
      prefix: generated.prefix,
      rawKey: generated.rawKey,
      scopes: input.scopes,
    };
  }

  async verifyApiKey(rawKey: string, now = Date.now()) {
    const keyHash = await sha256Hex(rawKey);
    const rows = await this.db
      .select()
      .from(schema.apiKeys)
      .where(eq(schema.apiKeys.keyHash, keyHash))
      .limit(1);

    const record = rows[0];
    if (!record) return null;
    if (record.revokedAt !== null) return null;
    if (record.expiresAt !== null && record.expiresAt <= now) return null;

    return {
      keyId: record.id,
      tenantId: record.tenantId,
      projectId: record.projectId,
      prefix: record.prefix,
      scopes: JSON.parse(record.scopesJson) as ApiKeyScope[],
    };
  }

  async revokeApiKey(tenantId: string, keyId: string) {
    await this.db
      .update(schema.apiKeys)
      .set({ revokedAt: Date.now() })
      .where(and(eq(schema.apiKeys.tenantId, tenantId), eq(schema.apiKeys.id, keyId)));
  }

  /**
   * Encrypts an upstream provider key (e.g. Gemini API key) with AES-256-GCM before saving.
   */
  async saveProviderCredential(input: {
    id: string;
    tenantId: string;
    provider: ProviderName;
    rawApiKey: string;
    baseUrl?: string;
  }) {
    if (input.baseUrl) {
      // Validate SSRF at configuration time as well as runtime
      const { validateSafeUpstreamUrl } = await import("../adapters/ssrf-guard.js");
      validateSafeUpstreamUrl(input.baseUrl);
    }

    const { encryptedHex, ivHex } = await encryptSecret(input.rawApiKey, this.encryptionSecret);

    await this.db.insert(schema.providerCredentials).values({
      id: input.id,
      tenantId: input.tenantId,
      provider: input.provider,
      baseUrl: input.baseUrl ?? null,
      encryptedApiKey: encryptedHex,
      iv: ivHex,
      createdAt: Date.now(),
    });
  }

  /**
   * Retrieves and decrypts the tenant's upstream credential for the given provider.
   */
  async getDecryptedProviderCredential(tenantId: string, provider: ProviderName) {
    const rows = await this.db
      .select()
      .from(schema.providerCredentials)
      .where(
        and(
          eq(schema.providerCredentials.tenantId, tenantId),
          eq(schema.providerCredentials.provider, provider)
        )
      )
      .orderBy(desc(schema.providerCredentials.createdAt))
      .limit(1);

    const row = rows[0];
    if (!row) return null;

    const apiKey = await decryptSecret(row.encryptedApiKey, row.iv, this.encryptionSecret);
    return {
      provider: row.provider,
      apiKey,
      baseUrl: row.baseUrl,
    };
  }

  async insertRequest(tenantId: string, req: Omit<typeof schema.requests.$inferInsert, "tenantId">) {
    await this.db.insert(schema.requests).values({
      ...req,
      tenantId,
    });
  }

  async getRequestById(tenantId: string, requestId: string) {
    const rows = await this.db
      .select()
      .from(schema.requests)
      .where(and(eq(schema.requests.tenantId, tenantId), eq(schema.requests.id, requestId)))
      .limit(1);

    return rows[0] ?? null;
  }

  async listRequests(tenantId: string, limit = 50) {
    return this.db
      .select()
      .from(schema.requests)
      .where(eq(schema.requests.tenantId, tenantId))
      .orderBy(desc(schema.requests.createdAt))
      .limit(limit);
  }
  async insertFindings(tenantId: string, requestId: string, items: import("@warden/policy-schema").Finding[]) {
    if (items.length === 0) return;
    const now = Date.now();
    await this.db.insert(schema.findings).values(
      items.map((f) => ({
        id: f.id,
        tenantId,
        requestId,
        detector: f.detector,
        ruleId: f.ruleId,
        owaspCategory: f.owaspCategory,
        confidence: f.confidence,
        action: f.action,
        direction: f.direction,
        evidenceStart: f.evidenceSpan.start,
        evidenceEnd: f.evidenceSpan.end,
        snippetRedacted: f.evidenceSpan.snippetRedacted,
        message: f.message,
        createdAt: now,
      }))
    );
  }

  async getFindingsByRequestId(tenantId: string, requestId: string) {
    return this.db
      .select()
      .from(schema.findings)
      .where(and(eq(schema.findings.tenantId, tenantId), eq(schema.findings.requestId, requestId)));
  }
  /**
   * Creates a new policy or appends a new immutable version to an existing policy,
   * then activates it as currentVersionId.
   */
  async savePolicyVersion(input: {
    tenantId: string;
    policyId: string;
    name: string;
    rawYamlOrJson: string;
    createdBy?: string;
  }) {
    const { parsePolicyYamlOrJson } = await import("@warden/policy-schema");
    const { policy, canonicalYaml } = parsePolicyYamlOrJson(input.rawYamlOrJson);
    const now = Date.now();

    const existingPolicy = await this.db
      .select()
      .from(schema.policies)
      .where(and(eq(schema.policies.tenantId, input.tenantId), eq(schema.policies.id, input.policyId)))
      .limit(1);

    const existingVersions = await this.db
      .select()
      .from(schema.policyVersions)
      .where(
        and(
          eq(schema.policyVersions.tenantId, input.tenantId),
          eq(schema.policyVersions.policyId, input.policyId)
        )
      )
      .orderBy(desc(schema.policyVersions.versionNumber));

    const nextVersionNumber = (existingVersions[0]?.versionNumber ?? 0) + 1;
    const versionId = `pver_${crypto.randomUUID()}`;

    if (existingPolicy.length === 0) {
      await this.db.insert(schema.policies).values({
        id: input.policyId,
        tenantId: input.tenantId,
        name: input.name,
        currentVersionId: versionId,
        createdAt: now,
      });
    }

    await this.db.insert(schema.policyVersions).values({
      id: versionId,
      tenantId: input.tenantId,
      policyId: input.policyId,
      versionNumber: nextVersionNumber,
      yamlContent: canonicalYaml,
      parsedJson: JSON.stringify(policy),
      createdBy: input.createdBy ?? "system",
      createdAt: now,
    });

    if (existingPolicy.length > 0) {
      await this.db
        .update(schema.policies)
        .set({ currentVersionId: versionId, name: input.name })
        .where(and(eq(schema.policies.tenantId, input.tenantId), eq(schema.policies.id, input.policyId)));
    }

    return {
      policyId: input.policyId,
      versionId,
      versionNumber: nextVersionNumber,
      policy,
      canonicalYaml,
    };
  }

  /**
   * Instant rollback: points a policy's currentVersionId to any previous immutable versionNumber.
   */
  async rollbackPolicyVersion(tenantId: string, policyId: string, targetVersionNumber: number) {
    const rows = await this.db
      .select()
      .from(schema.policyVersions)
      .where(
        and(
          eq(schema.policyVersions.tenantId, tenantId),
          eq(schema.policyVersions.policyId, policyId),
          eq(schema.policyVersions.versionNumber, targetVersionNumber)
        )
      )
      .limit(1);

    const target = rows[0];
    if (!target) {
      throw new Error(`Policy version ${targetVersionNumber} not found`);
    }

    await this.db
      .update(schema.policies)
      .set({ currentVersionId: target.id })
      .where(and(eq(schema.policies.tenantId, tenantId), eq(schema.policies.id, policyId)));

    const { PolicyDocumentSchema } = await import("@warden/policy-schema");
    return {
      versionId: target.id,
      versionNumber: target.versionNumber,
      policy: PolicyDocumentSchema.parse(JSON.parse(target.parsedJson)),
    };
  }

  /**
   * Creates or updates a project with an optional policy override.
   */
  async upsertProject(input: {
    id: string;
    tenantId: string;
    name: string;
    activePolicyId?: string | null;
  }) {
    const existing = await this.db
      .select()
      .from(schema.projects)
      .where(and(eq(schema.projects.tenantId, input.tenantId), eq(schema.projects.id, input.id)))
      .limit(1);

    if (existing.length === 0) {
      await this.db.insert(schema.projects).values({
        id: input.id,
        tenantId: input.tenantId,
        name: input.name,
        activePolicyId: input.activePolicyId ?? null,
        createdAt: Date.now(),
      });
    } else {
      await this.db
        .update(schema.projects)
        .set({ name: input.name, activePolicyId: input.activePolicyId ?? null })
        .where(and(eq(schema.projects.tenantId, input.tenantId), eq(schema.projects.id, input.id)));
    }
  }

  /**
   * Resolves the active PolicyDocument for a request:
   * 1. Project override policy (if projectId has activePolicyId)
   * 2. Tenant's latest active policy
   * 3. Fallback to DEFAULT_POLICY
   */
  async resolveEffectivePolicy(
    tenantId: string,
    projectId?: string | null
  ): Promise<import("@warden/policy-schema").PolicyDocument> {
    const { DEFAULT_POLICY, PolicyDocumentSchema } = await import("@warden/policy-schema");

    let targetPolicyId: string | null = null;

    if (projectId) {
      const projRows = await this.db
        .select()
        .from(schema.projects)
        .where(and(eq(schema.projects.tenantId, tenantId), eq(schema.projects.id, projectId)))
        .limit(1);
      targetPolicyId = projRows[0]?.activePolicyId ?? null;
    }

    let policyRow;
    if (targetPolicyId) {
      const rows = await this.db
        .select()
        .from(schema.policies)
        .where(and(eq(schema.policies.tenantId, tenantId), eq(schema.policies.id, targetPolicyId)))
        .limit(1);
      policyRow = rows[0];
    } else {
      const rows = await this.db
        .select()
        .from(schema.policies)
        .where(eq(schema.policies.tenantId, tenantId))
        .orderBy(desc(schema.policies.createdAt))
        .limit(1);
      policyRow = rows[0];
    }

    if (!policyRow?.currentVersionId) {
      return DEFAULT_POLICY;
    }

    const verRows = await this.db
      .select()
      .from(schema.policyVersions)
      .where(
        and(
          eq(schema.policyVersions.tenantId, tenantId),
          eq(schema.policyVersions.id, policyRow.currentVersionId)
        )
      )
      .limit(1);

    if (!verRows[0]) {
      return DEFAULT_POLICY;
    }

    return PolicyDocumentSchema.parse(JSON.parse(verRows[0].parsedJson));
  }

  async getPolicyVersionByNumber(tenantId: string, policyId: string, versionNumber: number) {
    const rows = await this.db
      .select()
      .from(schema.policyVersions)
      .where(
        and(
          eq(schema.policyVersions.tenantId, tenantId),
          eq(schema.policyVersions.policyId, policyId),
          eq(schema.policyVersions.versionNumber, versionNumber)
        )
      )
      .limit(1);
    return rows[0] ?? null;
  }
}