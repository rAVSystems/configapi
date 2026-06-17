import fs from "fs";
import { exec } from "child_process";
import type { FastifyInstance } from "fastify";
import { systemSettings } from "../db.js";
import { encryptField, decryptField } from "../crypto.js";
import { requireRole } from "../auth.js";
import type { SystemSettings } from "../types.js";

export const STACK_ENV_PATH = process.env.STACK_ENV_PATH || "/run/secrets/stack.env";

export function readEnvFileValue(filePath: string, key: string): string {
  try {
    const content = fs.readFileSync(filePath, "utf8");
    const line = content.split("\n").find(l => l.startsWith(`${key}=`) || l.startsWith(`${key} =`));
    if (!line) return "";
    return line.split("=").slice(1).join("=").replace(/^["']|["']$/g, "").trim();
  } catch { return ""; }
}

export function updateEnvFile(filePath: string, updates: Record<string, string>): void {
  let content = "";
  try { content = fs.readFileSync(filePath, "utf8"); } catch { /* file may not exist */ }
  const lines = content.split("\n");
  for (const [key, value] of Object.entries(updates)) {
    const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    const newLine = `${key}="${escaped}"`;
    const idx = lines.findIndex(l => l.startsWith(`${key}=`) || l.startsWith(`${key} =`));
    if (idx >= 0) lines[idx] = newLine;
    else lines.push(newLine);
  }
  fs.writeFileSync(filePath, lines.filter((l, i) => l !== "" || i === lines.length - 1).join("\n"), "utf8");
}

export async function settingsRoutes(app: FastifyInstance) {
  app.get("/settings/status", async () => {
    const doc = await systemSettings().findOne({ _id: "system" });
    return { setupComplete: doc?.setupComplete ?? false, portalName: doc?.portalName ?? "" };
  });

  app.get("/settings", { preHandler: requireRole("admin") }, async (_request, reply) => {
    const doc = await systemSettings().findOne({ _id: "system" });
    if (!doc) return reply.code(404).send({ error: "Settings not found" });

    return {
      setupComplete: doc.setupComplete,
      portalName: doc.portalName,
      apiCredentials: doc.apiCredentials ? { username: decryptField(doc.apiCredentials.username) } : null,
      openclawCredentials: doc.openclawCredentials ? { username: decryptField(doc.openclawCredentials.username) } : null,
      openclawLlmProvider: doc.openclawLlmProvider ?? "",
      openclawLlmModel: doc.openclawLlmModel ?? "",
      openclawLlmKeySet: !!doc.openclawLlmApiKey,
      openclawModelCache: (doc as any).openclawModelCache ?? [],
      openclawSkills: (doc as any).openclawSkills ?? [],
      openclawChannels: (doc.openclawChannels ?? []).map(c => ({
        name: c.name,
        tokenSet: !!c.token,
      })),
      mqttCredentials: doc.mqttCredentials ? { username: decryptField(doc.mqttCredentials.username) } : null,
      dbCredentials: doc.dbCredentials ? { username: decryptField(doc.dbCredentials.username) } : null,
    };
  });

  app.put("/settings", { preHandler: requireRole("admin") }, async (request) => {
    const body = request.body as any;
    const now = new Date();

    const update: Partial<SystemSettings> = {
      updatedAt: now,
      updatedBy: request.user.username,
    };

    if (body.portalName !== undefined) update.portalName = body.portalName;
    if (body.setupComplete !== undefined) update.setupComplete = body.setupComplete;

    if (body.apiCredentials?.username) update.apiCredentials = {
      username: encryptField(body.apiCredentials.username),
      password: encryptField(body.apiCredentials.password),
    };
    if (body.anthropicApiKey) update.anthropicApiKey = encryptField(body.anthropicApiKey);
    if (body.openclawCredentials?.username) update.openclawCredentials = {
      username: encryptField(body.openclawCredentials.username),
      password: encryptField(body.openclawCredentials.password),
    };
    if (body.openclawLlmProvider !== undefined) update.openclawLlmProvider = body.openclawLlmProvider;
    if (body.openclawLlmModel !== undefined) update.openclawLlmModel = body.openclawLlmModel;
    if (Array.isArray(body.openclawSkills)) update.openclawSkills = body.openclawSkills;
    if (Array.isArray(body.openclawChannels)) {
      update.openclawChannels = body.openclawChannels.map((c: { name: string; token: string }) => ({
        name: c.name,
        token: encryptField(c.token ?? ""),
      }));
    }
    if (body.mqttCredentials?.username) update.mqttCredentials = {
      username: encryptField(body.mqttCredentials.username),
      password: encryptField(body.mqttCredentials.password),
    };
    if (body.dbCredentials?.username) update.dbCredentials = {
      username: encryptField(body.dbCredentials.username),
      password: encryptField(body.dbCredentials.password),
    };

    await systemSettings().updateOne(
      { _id: "system" },
      { $set: update },
      { upsert: true }
    );

    return { success: true };
  });

  app.post("/settings/reset-mongo-password", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { password } = request.body as any;
    if (!password || password.length < 6) return reply.code(400).send({ error: "Password must be at least 6 characters" });
    try {
      const rootUsername = process.env.MONGO_ROOT_USERNAME || "admin";
      const currentPassword = readEnvFileValue(STACK_ENV_PATH, "MONGO_ROOT_PASSWORD") || "admin";
      await new Promise<void>((resolve, reject) => {
        exec(
          `docker exec av-mongo mongosh -u ${rootUsername} -p ${JSON.stringify(currentPassword)} --authenticationDatabase admin --eval ${JSON.stringify(`db.getSiblingDB('admin').updateUser('${rootUsername}', {pwd: '${password}'})`) } --quiet`,
          (err, _stdout, stderr) => err ? reject(new Error(stderr || err.message)) : resolve()
        );
      });
      updateEnvFile(STACK_ENV_PATH, { MONGO_ROOT_PASSWORD: password });
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/settings/openclaw-key", { preHandler: requireRole("admin") }, async (_request, reply) => {
    const doc = await systemSettings().findOne({ _id: "system" });
    if (!doc?.anthropicApiKey) return reply.code(404).send({ error: "Anthropic API key not configured" });
    return { apiKey: decryptField(doc.anthropicApiKey) };
  });
}
