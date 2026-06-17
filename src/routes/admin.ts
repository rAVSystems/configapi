import type { FastifyInstance } from "fastify";
import { users } from "../db.js";
import { hashPasswordScrypt } from "../crypto.js";
import { requireRole } from "../auth.js";
import type { Role } from "../types.js";

export async function adminRoutes(app: FastifyInstance) {
  app.get("/admin/users", { preHandler: requireRole("admin") }, async () => {
    const docs = await users()
      .find({}, {
        projection: {
          _id: 1,
          "user.username": 1,
          "user.roles": 1,
          "user.isActive": 1,
          "user.createdAt": 1,
          "user.lastLoginAt": 1,
        } as any,
      })
      .sort({ "user.username": 1 })
      .toArray();

    return docs.map((d) => ({
      _id: d._id,
      username: d.user.username,
      roles: d.user.roles,
      isActive: d.user.isActive,
      createdAt: d.user.createdAt,
      lastLoginAt: d.user.lastLoginAt ?? null,
    }));
  });

  app.patch("/admin/users/:id/roles", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const roles: Role[] = body?.roles;

    const validRoles = ["admin", "editor", "viewer"];
    if (!Array.isArray(roles) || roles.length === 0 || roles.some((r) => !validRoles.includes(r))) {
      return reply.code(400).send({ error: "roles must be a non-empty array of admin|editor|viewer" });
    }

    const res = await users().updateOne(
      { _id: id },
      { $set: { "user.roles": roles, "user.updatedAt": new Date() } }
    );
    if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

    return { success: true };
  });

  app.patch("/admin/users/:id/username", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const username = String(body?.username ?? "").trim();

    if (!username || username.length < 3 || username.length > 50) {
      return reply.code(400).send({ error: "Username must be 3-50 characters" });
    }

    const existing = await users().findOne(
      { "user.username": username },
      { projection: { _id: 1 } as any }
    );
    if (existing && existing._id !== id) {
      return reply.code(409).send({ error: "Username already taken" });
    }

    const res = await users().updateOne(
      { _id: id },
      { $set: { "user.username": username, "user.updatedAt": new Date() } }
    );
    if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

    return { success: true };
  });

  app.patch("/admin/users/:id/password", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;
    const password = String(body?.password ?? "");

    if (!password || password.length < 8 || password.length > 200) {
      return reply.code(400).send({ error: "Password must be at least 8 characters" });
    }

    const passwordHash = hashPasswordScrypt(password);
    const res = await users().updateOne(
      { _id: id },
      { $set: { "user.passwordHash": passwordHash, "user.updatedAt": new Date() } }
    );
    if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

    return { success: true };
  });

  app.patch("/admin/users/:id/active", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as any;

    if (typeof body?.isActive !== "boolean") {
      return reply.code(400).send({ error: "isActive must be a boolean" });
    }

    const res = await users().updateOne(
      { _id: id },
      { $set: { "user.isActive": body.isActive, "user.updatedAt": new Date() } }
    );
    if (res.matchedCount === 0) return reply.code(404).send({ error: "User not found" });

    return { success: true };
  });

  app.delete("/admin/users/:id", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const user = await users().findOne({ _id: id }, { projection: { "user.username": 1 } as any });
    if (!user) return reply.code(404).send({ error: "User not found" });

    const username = (user as any).user?.username;
    if (username === "admin") {
      return reply.code(403).send({ error: "Cannot delete the built-in admin account" });
    }

    const res = await users().deleteOne({ _id: id });
    if (res.deletedCount === 0) return reply.code(404).send({ error: "User not found" });

    return { success: true };
  });
}
