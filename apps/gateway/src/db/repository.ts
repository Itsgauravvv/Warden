import { and, desc, eq } from "drizzle-orm";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "./schema.js";
import { generateTenantApiKey, sha256Hex, type ApiKeyScope } from "../auth/api-key.js";

export type WardenDb = BaseSQLiteDatabase<"sync" | "async", unknown, typeof schema>;

export class TenantRepository {
  constructor(private readonly db: WardenDb) {}

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

  /**
   * Issues a new API key for a specific tenant. Returns rawKey ONCE; stores only keyHash.
   */
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
      rawKey: generated.rawKey, // Shown once!
      scopes: input.scopes,
    };
  }

  /**
   * Authenticates a Bearer token by hashing it and checking revocation + expiry.
   */
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

  /**
   * Instant key revocation scoped strictly to the owning tenant.
   */
  async revokeApiKey(tenantId: string, keyId: string) {
    await this.db
      .update(schema.apiKeys)
      .set({ revokedAt: Date.now() })
      .where(and(eq(schema.apiKeys.tenantId, tenantId), eq(schema.apiKeys.id, keyId)));
  }

  /**
   * Strictly tenant-scoped request insertion.
   */
  async insertRequest(tenantId: string, req: Omit<typeof schema.requests.$inferInsert, "tenantId">) {
    await this.db.insert(schema.requests).values({
      ...req,
      tenantId,
    });
  }

  /**
   * Strictly tenant-scoped request lookup.
   * Cross-tenant reads are impossible because tenantId is enforced in the WHERE clause.
   */
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
}