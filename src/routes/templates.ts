import { v4 as uuidv4 } from "uuid";
import type { FastifyInstance } from "fastify";
import { templates } from "../db.js";
import { requireAnyRole } from "../auth.js";
import type { TemplateDoc } from "../types.js";

export async function templateRoutes(app: FastifyInstance) {
  app.get("/templates", async () => {
    return templates()
      .find({}, { projection: { _id: 1, name: 1, icon: 1, createdby: 1, created: 1, permission: 1 } })
      .sort({ name: 1 })
      .toArray();
  });

  app.get("/templates/mine", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request) => {
    return templates()
      .find(
        { createdby: request.user.username },
        { projection: { _id: 1, name: 1, icon: 1, createdby: 1, created: 1, permission: 1 } }
      )
      .toArray();
  });

  app.get("/templates/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const doc = await templates().findOne({ _id: id });
    if (!doc) return reply.code(404).send({ error: "Template not found" });
    return doc;
  });

  app.post("/templates", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body as any;
    if (!body?.name) return reply.code(400).send({ error: "name is required" });

    const doc: TemplateDoc = {
      _id: uuidv4(),
      name: body.name,
      icon: body.icon ?? "description",
      createdby: request.user.username,
      created: new Date().toISOString(),
      permission: body.permission ?? "user",
      config: body.config ?? {},
    };

    await templates().insertOne(doc);
    return reply.code(201).send({ success: true, _id: doc._id });
  });

  app.patch("/templates/:id", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const body = request.body as { name?: string; permission?: string; config?: any };
    const isAdmin = request.user.roles.includes("admin");

    const doc = await templates().findOne({ _id: id });
    if (!doc) return reply.code(404).send({ error: "Template not found" });

    if (!isAdmin) {
      if (doc.createdby !== request.user.username) {
        return reply.code(403).send({ error: "Not authorized to edit this template" });
      }
      if (body.permission !== undefined) {
        return reply.code(403).send({ error: "Only admins can change template permission" });
      }
    }

    const update: any = {};
    if (body.name !== undefined) update.name = body.name;
    if (body.permission !== undefined) update.permission = body.permission;
    if (body.config !== undefined) update.config = body.config;

    if (Object.keys(update).length === 0) return reply.code(400).send({ error: "Nothing to update" });
    await templates().updateOne({ _id: id }, { $set: update });
    return { success: true };
  });

  app.delete("/templates/:id", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const isAdmin = request.user.roles.includes("admin");

    const doc = await templates().findOne({ _id: id });
    if (!doc) return reply.code(404).send({ error: "Template not found" });

    if (!isAdmin && doc.createdby !== request.user.username) {
      return reply.code(403).send({ error: "Not authorized to delete this template" });
    }

    if (!isAdmin && doc.permission === "admin") {
      return reply.code(403).send({ error: "This template has been promoted to admin-only and cannot be deleted by its creator" });
    }

    await templates().deleteOne({ _id: id });
    return { success: true };
  });
}
