import fs from "fs";
import { v4 as uuidv4 } from "uuid";
import type { FastifyBaseLogger } from "fastify";
import { users, templates } from "./db.js";
import { hashPasswordScrypt, verifyPasswordScrypt, encryptField } from "./crypto.js";
import { systemSettings } from "./db.js";
import type { AppUserDoc } from "./types.js";

async function ensureUser(args: {
  username: string;
  password: string;
  roles: ("admin" | "editor" | "viewer")[];
  mustChangePassword?: boolean;
  log: FastifyBaseLogger;
}): Promise<void> {
  const { username, password, roles, mustChangePassword, log } = args;

  const existing = await users().findOne({ "user.username": username });

  if (existing) {
    if (mustChangePassword && verifyPasswordScrypt(password, existing.user.passwordHash)) {
      await users().updateOne(
        { "user.username": username },
        { $set: { "user.mustChangePassword": true, "user.updatedAt": new Date() } }
      );
    }
    return;
  }

  const now = new Date();
  const doc: AppUserDoc = {
    _id: uuidv4(),
    user: {
      username,
      passwordHash: hashPasswordScrypt(password),
      roles,
      isActive: true,
      mustChangePassword: mustChangePassword ?? false,
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null,
    },
  };

  await users().insertOne(doc);
  log.info({ username, roles }, "Bootstrapped default user");
}

export async function ensureDefaultUsers(log: FastifyBaseLogger): Promise<void> {
  const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
  const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "admin";
  await ensureUser({ username: adminUsername, password: adminPassword, roles: ["admin"], mustChangePassword: true, log });
}

export async function ensureDefaultTemplates(log: FastifyBaseLogger): Promise<void> {
  const count = await templates().countDocuments();
  if (count > 0) return;

  const templateDir = "/app/templates";
  try {
    const files = fs.readdirSync(templateDir).filter(f => f.endsWith(".json"));
    for (const file of files) {
      try {
        const doc = JSON.parse(fs.readFileSync(`${templateDir}/${file}`, "utf8"));
        if (doc._id) await templates().insertOne(doc);
      } catch { /* skip malformed files */ }
    }
    log.info({ count: files.length }, "Seeded default templates");
  } catch { /* templates dir not mounted, skip */ }
}

export async function ensureDefaultSettings(log: FastifyBaseLogger): Promise<void> {
  const existing = await systemSettings().findOne({ _id: "system" });
  if (existing) return;

  const placeholder = encryptField("not-configured");
  await systemSettings().insertOne({
    _id: "system",
    setupComplete: false,
    portalName: "AV Portal",
    apiCredentials: { username: placeholder, password: placeholder },
    anthropicApiKey: placeholder,
    openclawCredentials: { username: placeholder, password: placeholder },
    openclawLlmProvider: "",
    openclawLlmModel: "",
    openclawLlmApiKey: placeholder,
    openclawSkills: [],
    openclawChannels: [],
    mqttCredentials: { username: placeholder, password: placeholder },
    dbCredentials: { username: placeholder, password: placeholder },
    updatedAt: new Date(),
    updatedBy: "system",
  });
  log.info("Seeded default settings document");
}
