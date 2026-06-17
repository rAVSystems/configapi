import { v4 as uuidv4 } from "uuid";
import type { FastifyInstance } from "fastify";
import { users } from "../db.js";
import { hashPasswordScrypt, verifyPasswordScrypt } from "../crypto.js";
import { requireAnyRole } from "../auth.js";
import type { AppUserDoc, Role } from "../types.js";

export async function authRoutes(app: FastifyInstance) {
  app.post("/auth/login", async (request, reply) => {
    const body = request.body as any;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");

    if (!username || !password) {
      return reply.code(400).send({ error: "Username and password required" });
    }

    // Service account: check env vars directly, no DB lookup
    const serviceUsername = process.env.OPENCLAW_API_USERNAME || "api";
    const servicePassword = process.env.OPENCLAW_API_PASSWORD || "api-default";
    if (username === serviceUsername && password === servicePassword) {
      const token = await reply.jwtSign({ sub: "service", username, roles: ["editor"] });
      return reply.send({ token, user: { username, roles: ["editor"], mustChangePassword: false } });
    }

    const doc = await users().findOne({ "user.username": username });
    if (!doc) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    if (!doc.user.isActive) {
      return reply.code(403).send({ error: "Account disabled" });
    }

    const ok = verifyPasswordScrypt(password, doc.user.passwordHash);
    if (!ok) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }

    const now = new Date();
    await users().updateOne(
      { _id: doc._id },
      { $set: { "user.lastLoginAt": now, "user.updatedAt": now } }
    );

    const token = await reply.jwtSign({
      sub: doc._id,
      username: doc.user.username,
      roles: doc.user.roles,
    });

    return reply.send({
      token,
      user: {
        username: doc.user.username,
        roles: doc.user.roles,
        mustChangePassword: doc.user.mustChangePassword ?? false,
      },
    });
  });

  app.post("/auth/register", async (request, reply) => {
    const body = request.body as any;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");

    const requestedRoleRaw = String(body?.role ?? "editor").toLowerCase();
    const role: "viewer" | "editor" = requestedRoleRaw === "viewer" ? "viewer" : "editor";

    if (!username || !password) {
      return reply.code(400).send({ error: "Username and password required" });
    }
    if (username.length < 3 || username.length > 50) {
      return reply.code(400).send({ error: "Username must be 3-50 characters" });
    }
    if (password.length < 8 || password.length > 200) {
      return reply.code(400).send({ error: "Password must be at least 8 characters" });
    }

    const existing = await users().findOne(
      { "user.username": username },
      { projection: { _id: 1 } as any }
    );
    if (existing) {
      return reply.code(409).send({ error: "Username already exists" });
    }

    const now = new Date();
    const doc: AppUserDoc = {
      _id: uuidv4(),
      user: {
        username,
        passwordHash: hashPasswordScrypt(password),
        roles: [role],
        isActive: true,
        createdAt: now,
        updatedAt: now,
        lastLoginAt: null,
      },
    };

    await users().insertOne(doc);

    const token = await reply.jwtSign({
      sub: doc._id,
      username: doc.user.username,
      roles: doc.user.roles,
    });

    return reply.code(201).send({
      token,
      user: { username: doc.user.username, roles: doc.user.roles },
    });
  });

  app.patch(
    "/auth/change-password",
    { preHandler: requireAnyRole(["admin", "editor", "viewer"]) },
    async (request, reply) => {
      const body = request.body as any;
      const currentPassword = String(body?.currentPassword ?? "");
      const newPassword = String(body?.newPassword ?? "");

      if (!currentPassword || !newPassword) {
        return reply.code(400).send({ error: "currentPassword and newPassword are required" });
      }
      if (newPassword.length < 8 || newPassword.length > 200) {
        return reply.code(400).send({ error: "New password must be at least 8 characters" });
      }

      const doc = await users().findOne({ _id: request.user.sub });
      if (!doc) return reply.code(404).send({ error: "User not found" });

      const ok = verifyPasswordScrypt(currentPassword, doc.user.passwordHash);
      if (!ok) return reply.code(401).send({ error: "Current password is incorrect" });

      const now = new Date();
      await users().updateOne(
        { _id: doc._id },
        { $set: { "user.passwordHash": hashPasswordScrypt(newPassword), "user.mustChangePassword": false, "user.updatedAt": now } }
      );

      return reply.send({ success: true });
    }
  );

  // Self-service profile
  app.patch(
    "/auth/me/username",
    { preHandler: requireAnyRole(["admin", "editor", "viewer"]) },
    async (request, reply) => {
      const body = request.body as any;
      const username = String(body?.username ?? "").trim();

      if (!username || username.length < 3 || username.length > 50) {
        return reply.code(400).send({ error: "Username must be 3-50 characters" });
      }

      const existing = await users().findOne({ "user.username": username }, { projection: { _id: 1 } as any });
      if (existing && existing._id !== request.user.sub) {
        return reply.code(409).send({ error: "Username already taken" });
      }

      const res = await users().updateOne(
        { _id: request.user.sub },
        { $set: { "user.username": username, "user.updatedAt": new Date() } }
      );
      if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

      const token = await reply.jwtSign({ sub: request.user.sub, username, roles: request.user.roles });
      return reply.send({ token, user: { username, roles: request.user.roles } });
    }
  );

  app.patch(
    "/auth/me/password",
    { preHandler: requireAnyRole(["admin", "editor", "viewer"]) },
    async (request, reply) => {
      const body = request.body as any;
      const password = String(body?.password ?? "");

      if (!password || password.length < 8 || password.length > 200) {
        return reply.code(400).send({ error: "Password must be at least 8 characters" });
      }

      const passwordHash = hashPasswordScrypt(password);
      const res = await users().updateOne(
        { _id: request.user.sub },
        { $set: { "user.passwordHash": passwordHash, "user.mustChangePassword": false, "user.updatedAt": new Date() } }
      );
      if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

      return { success: true };
    }
  );
}
