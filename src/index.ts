import Fastify from "fastify";
import jwt from "@fastify/jwt";
import cors from "@fastify/cors";

import { client, initDb, roomConfigs, users, templates, usageEvents, reports } from "./db.js";
import { initMqtt } from "./mqtt.js";
import { ensureDefaultUsers, ensureDefaultTemplates, ensureDefaultSettings } from "./bootstrap.js";

import { authRoutes } from "./routes/auth.js";
import { roomRoutes } from "./routes/rooms.js";
import { templateRoutes } from "./routes/templates.js";
import { reportRoutes } from "./routes/reports.js";
import { settingsRoutes } from "./routes/settings.js";
import { openclawRoutes } from "./routes/openclaw.js";
import { adminRoutes } from "./routes/admin.js";
import { schedulerRoutes } from "./routes/scheduler.js";

const app = Fastify({ logger: true, bodyLimit: 10485760 }); // 10MB

app.register(cors, {
  origin: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
});

app.get("/health", async () => ({ status: "ok" }));

const start = async () => {
  await client.connect();
  const db = client.db("avdb");
  initDb(db);

  await app.register(jwt, {
    secret: process.env.JWT_SECRET || "dev-secret-change-me",
  });

  initMqtt(app.log);

  // Register all route modules
  await app.register(authRoutes);
  await app.register(roomRoutes);
  await app.register(templateRoutes);
  await app.register(reportRoutes);
  await app.register(settingsRoutes);
  await app.register(openclawRoutes);
  await app.register(adminRoutes);
  await app.register(schedulerRoutes);

  // Indexes (idempotent)
  await roomConfigs().createIndex({ "config.ip": 1 });
  await roomConfigs().createIndex({ "config.campus": 1, "config.building": 1, "config.room": 1 });
  await users().createIndex({ "user.username": 1 }, { unique: true });
  await templates().createIndex({ _id: 1 });
  await usageEvents().createIndex({ roomId: 1, timestamp: -1 });
  await usageEvents().createIndex({ timestamp: -1 });
  await reports().createIndex({ createdAt: -1 });

  // Seed defaults
  await ensureDefaultSettings(app.log);
  await ensureDefaultUsers(app.log);
  await ensureDefaultTemplates(app.log);

  await app.listen({ port: 8080, host: "0.0.0.0" });
  console.log("API running on port 8080");
};

start();
