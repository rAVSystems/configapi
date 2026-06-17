import { v4 as uuidv4 } from "uuid";
import type { FastifyInstance } from "fastify";
import { roomConfigs, roomStates, usageEvents, ROOM_SUMMARY_PROJECTION } from "../db.js";
import { mqttClient } from "../mqtt.js";
import { requireAuth, requireAnyRole, requireRole, getClientIp } from "../auth.js";
import type { RoomConfig, UsageEventDoc } from "../types.js";

const MEDIAMTX_HOST = process.env.MEDIAMTX_HOST || "192.168.1.225";
const MEDIAMTX_WEBRTC_PORT = process.env.MEDIAMTX_WEBRTC_PORT || "8889";
const MEDIAMTX_HLS_PORT = process.env.MEDIAMTX_HLS_PORT || "8888";

// Tracks rooms that have a pending sync request.
// The QSys core polls GET /rooms/:roomId/sync-status and clears it once synced.
const pendingSyncs = new Set<string>();

async function upsertRoomConfig(args: {
  roomId: string;
  incoming: Record<string, unknown>;
  updatedBy: string;
}): Promise<{ roomId: string; version: number | null }> {
  const { roomId, incoming, updatedBy } = args;

  const config: RoomConfig = {
    ...(incoming as any),
    roomId,
    updatedAt: new Date(),
    updatedBy,
  };

  await roomConfigs().updateOne(
    { _id: roomId },
    { $set: { _id: roomId, config } },
    { upsert: true }
  );

  return { roomId, version: (incoming as any)?.version ?? null };
}

export async function roomRoutes(app: FastifyInstance) {
  // ── Config ────────────────────────────────────────────────────────────────

  app.get("/rooms", async (request) => {
    const { campus, building } = request.query as { campus?: string; building?: string };

    const filter: Record<string, unknown> = {};
    if (campus) filter["config.campus"] = campus;
    if (building) filter["config.building"] = building;

    return roomConfigs()
      .find(filter, { projection: ROOM_SUMMARY_PROJECTION as any })
      .sort({ "config.campus": 1, "config.building": 1, "config.room": 1 })
      .toArray();
  });

  app.get("/rooms/:roomId", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1, config: 1 } });
    if (!room) return reply.code(404).send({ error: "Room not found" });
    return room;
  });

  app.get("/campuses/:campus/rooms", async (request) => {
    const { campus } = request.params as { campus: string };
    return roomConfigs()
      .find({ "config.campus": campus }, { projection: ROOM_SUMMARY_PROJECTION as any })
      .sort({ "config.building": 1, "config.room": 1 })
      .toArray();
  });

  app.get("/campuses/:campus/buildings/:building/rooms", async (request) => {
    const { campus, building } = request.params as { campus: string; building: string };
    return roomConfigs()
      .find(
        { "config.campus": campus, "config.building": building },
        { projection: ROOM_SUMMARY_PROJECTION as any }
      )
      .sort({ "config.room": 1 })
      .toArray();
  });

  app.get("/config/by-client-ip", async (request, reply) => {
    const clientIp = getClientIp(request);
    if (!clientIp) return reply.code(400).send({ error: "Unable to determine client IP" });

    const doc = await roomConfigs().findOne({ "config.ip": clientIp }, { projection: { _id: 1, config: 1 } });
    if (!doc) return reply.code(404).send({ error: "No config found for client IP", ip: clientIp });

    return doc;
  });

  app.post("/rooms", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body as unknown;
    if (body === null || body === undefined || typeof body !== "object") {
      return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }

    const roomId = uuidv4();
    const result = await upsertRoomConfig({ roomId, incoming: body as Record<string, unknown>, updatedBy: request.user.username });
    return reply.code(201).send({ success: true, roomId: result.roomId, version: result.version });
  });

  // Backwards-compatible alias: treat PUT /rooms as create-with-guid as well
  app.put("/rooms", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body as unknown;
    if (body === null || body === undefined || typeof body !== "object") {
      return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }

    const roomId = uuidv4();
    const result = await upsertRoomConfig({ roomId, incoming: body as Record<string, unknown>, updatedBy: request.user.username });
    return reply.code(201).send({ success: true, roomId: result.roomId, version: result.version });
  });

  app.put("/rooms/:roomId", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const { roomId } = request.params as { roomId: string };

    if (typeof roomId !== "string" || roomId.trim().length === 0) {
      return reply.code(400).send({ success: false, error: "roomId must be a non-empty string" });
    }

    const body = request.body as unknown;
    if (body === null || body === undefined || typeof body !== "object") {
      return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }

    const result = await upsertRoomConfig({ roomId, incoming: body as Record<string, unknown>, updatedBy: request.user.username });
    return { success: true, roomId: result.roomId, version: result.version };
  });

  app.delete("/rooms/:roomId", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const res = await roomConfigs().deleteOne({ _id: roomId });
    if (res.deletedCount === 0) return reply.code(404).send({ error: "Room not found" });
    return { success: true, roomId };
  });

  // ── Sync ──────────────────────────────────────────────────────────────────

  app.post("/rooms/:roomId/sync", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1 } });
    if (!room) return reply.code(404).send({ error: "Room not found" });
    pendingSyncs.add(roomId);
    return { success: true, roomId };
  });

  app.get("/rooms/:roomId/sync-status", { preHandler: requireAuth }, async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const pending = pendingSyncs.has(roomId);
    if (pending) pendingSyncs.delete(roomId);
    return { roomId, syncRequested: pending };
  });

  // ── State ─────────────────────────────────────────────────────────────────

  app.get("/rooms/states", async () => {
    return roomStates().find({}).toArray();
  });

  app.get("/rooms/:roomId/state", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const doc = await roomStates().findOne({ _id: roomId });
    if (!doc) return reply.code(404).send({ error: "No state found for this room" });
    return doc;
  });

  app.patch("/rooms/:roomId/state", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const body = request.body as Record<string, unknown>;

    if (!body || typeof body !== "object") {
      return reply.code(400).send({ error: "Body must be a JSON object" });
    }

    await roomStates().updateOne(
      { _id: roomId },
      { $set: { ...body, _id: roomId, updatedAt: new Date() } },
      { upsert: true }
    );

    mqttClient.publish(
      `av/rooms/${roomId}/state`,
      JSON.stringify({ roomId, ...body, updatedAt: new Date().toISOString() }),
      { retain: true, qos: 0 }
    );

    return { success: true };
  });

  // ── Usage ─────────────────────────────────────────────────────────────────

  app.post("/rooms/:roomId/usage", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const body = request.body as unknown;

    const events = Array.isArray(body) ? body : [body];
    if (events.length === 0) return reply.code(400).send({ error: "No events provided" });

    const now = new Date();
    const docs: UsageEventDoc[] = events.map((e: any) => ({
      _id: uuidv4(),
      roomId,
      timestamp: e.timestamp ? new Date(e.timestamp) : now,
      event: String(e.event ?? "unknown"),
      payload: e.payload ?? {},
    }));

    await usageEvents().insertMany(docs);
    return reply.code(201).send({ inserted: docs.length });
  });

  app.get("/rooms/:roomId/usage", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const { from, to, event, limit } = request.query as {
      from?: string; to?: string; event?: string; limit?: string;
    };

    const filter: Record<string, unknown> = { roomId };
    if (from || to) {
      const range: Record<string, Date> = {};
      if (from) range.$gte = new Date(from);
      if (to) range.$lte = new Date(to);
      filter.timestamp = range;
    }
    if (event) filter.event = event;

    return usageEvents()
      .find(filter)
      .sort({ timestamp: -1 })
      .limit(Number(limit ?? 500))
      .toArray();
  });

  app.get("/usage", async (request) => {
    const { from, to, event, roomId, limit } = request.query as {
      from?: string; to?: string; event?: string; roomId?: string; limit?: string;
    };

    const filter: Record<string, unknown> = {};
    if (roomId) filter.roomId = roomId;
    if (event) filter.event = event;
    if (from || to) {
      const range: Record<string, Date> = {};
      if (from) range.$gte = new Date(from);
      if (to) range.$lte = new Date(to);
      filter.timestamp = range;
    }

    return usageEvents()
      .find(filter)
      .sort({ timestamp: -1 })
      .limit(Number(limit ?? 1000))
      .toArray();
  });

  // ── Streams ───────────────────────────────────────────────────────────────

  app.get("/rooms/:roomId/streams", async (request, reply) => {
    const { roomId } = request.params as { roomId: string };
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1, config: 1 } });
    if (!room) return reply.code(404).send({ error: "Room not found" });

    const devices = (room.config.Devices ?? {}) as Record<string, any>;
    const streams: { name: string; rtsp: string; webrtc: string; hls: string }[] = [];

    for (const [key, device] of Object.entries(devices)) {
      const rtspUrl: string | undefined = device.RtspUrl;
      if (!rtspUrl) continue;

      const pathName = `${roomId}/${key}`.toLowerCase().replace(/[^a-z0-9/_-]/g, "-");

      streams.push({
        name: device.FriendlyName ?? key,
        rtsp: rtspUrl,
        webrtc: `http://${MEDIAMTX_HOST}:${MEDIAMTX_WEBRTC_PORT}/${pathName}`,
        hls: `http://${MEDIAMTX_HOST}:${MEDIAMTX_HLS_PORT}/${pathName}`,
      });
    }

    return { roomId, streams };
  });
}
