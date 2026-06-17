import { v4 as uuidv4 } from "uuid";
import type { FastifyInstance } from "fastify";
import { reports } from "../db.js";
import { requireRole } from "../auth.js";
import type { ReportDoc } from "../types.js";

export async function reportRoutes(app: FastifyInstance) {
  app.get("/reports", async () => {
    return reports()
      .find({}, { projection: { _id: 1, title: 1, createdAt: 1, createdBy: 1 } })
      .sort({ createdAt: -1 })
      .toArray();
  });

  app.get("/reports/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const doc = await reports().findOne({ _id: id });
    if (!doc) return reply.code(404).send({ error: "Report not found" });
    return doc;
  });

  app.post("/reports", async (request, reply) => {
    const body = request.body as any;
    const title = String(body?.title ?? "").trim();
    const reportBody = String(body?.body ?? "").trim();
    const createdBy = String(body?.createdBy ?? "system").trim();

    if (!title) return reply.code(400).send({ error: "title is required" });
    if (!reportBody) return reply.code(400).send({ error: "body is required" });

    const doc: ReportDoc = {
      _id: uuidv4(),
      title,
      createdAt: new Date(),
      createdBy,
      body: reportBody,
    };

    await reports().insertOne(doc);
    return reply.code(201).send({ success: true, id: doc._id });
  });

  app.delete("/reports/:id", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const res = await reports().deleteOne({ _id: id });
    if (res.deletedCount === 0) return reply.code(404).send({ error: "Report not found" });
    return { success: true };
  });
}
