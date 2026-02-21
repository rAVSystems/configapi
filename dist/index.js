import Fastify from "fastify";
import jwt from "@fastify/jwt";
import cors from "@fastify/cors";
import { MongoClient } from "mongodb";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
const app = Fastify({ logger: true });
// CORS (needed for browser-based clients like the Angular portal)
// Register early so preflight OPTIONS always gets the right headers.
app.register(cors, {
    origin: true, // reflect request Origin (dev-friendly)
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
});
const MONGO_URI = process.env.MONGO_URI ||
    "mongodb://avapp:avrocks@192.168.1.225:27017/avdb?authSource=avdb";
const client = new MongoClient(MONGO_URI);
let db;
const roomConfigs = () => db.collection("rooms");
const ROOM_SUMMARY_PROJECTION = {
    _id: 1,
    "config.campus": 1,
    "config.building": 1,
    "config.room": 1,
    "config.ip": 1,
    "config.roomType": 1,
    "config.version": 1,
    "config.updatedAt": 1,
    "config.updatedBy": 1,
};
const users = () => db.collection("users");
function hashPasswordScrypt(password) {
    // Store as: scrypt:<saltHex>:<hashHex>
    const salt = crypto.randomBytes(16);
    const hash = crypto.scryptSync(password, salt, 32);
    return `scrypt:${salt.toString("hex")}:${hash.toString("hex")}`;
}
function verifyPasswordScrypt(password, stored) {
    // stored: scrypt:<saltHex>:<hashHex>
    const parts = stored.split(":");
    if (parts.length !== 3)
        return false;
    const [algo, saltHex, hashHex] = parts;
    if (algo !== "scrypt" || !saltHex || !hashHex)
        return false;
    const salt = Buffer.from(saltHex, "hex");
    const expected = Buffer.from(hashHex, "hex");
    const actual = crypto.scryptSync(password, salt, expected.length);
    // timing safe compare
    return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}
async function ensureUser(args) {
    const { username, password, roles } = args;
    const existing = await users().findOne({ "user.username": username }, { projection: { _id: 1 } });
    if (existing)
        return;
    const now = new Date();
    const doc = {
        _id: uuidv4(),
        user: {
            username,
            passwordHash: hashPasswordScrypt(password),
            roles,
            isActive: true,
            createdAt: now,
            updatedAt: now,
            lastLoginAt: null,
        },
    };
    await users().insertOne(doc);
    app.log.info({ username, roles }, "Bootstrapped default user");
}
async function ensureDefaultUsers() {
    // For demos: defaults are provided if env vars are not set.
    // Set these in docker-compose for safer behavior.
    const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
    const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "admin";
    const apiUsername = process.env.BOOTSTRAP_API_USERNAME || "api";
    const apiPassword = process.env.BOOTSTRAP_API_PASSWORD || "api";
    if (!process.env.BOOTSTRAP_ADMIN_PASSWORD) {
        app.log.warn("BOOTSTRAP_ADMIN_PASSWORD is not set; using default 'admin'. Set env vars before production.");
    }
    if (!process.env.BOOTSTRAP_API_PASSWORD) {
        app.log.warn("BOOTSTRAP_API_PASSWORD is not set; using default 'api'. Set env vars before production.");
    }
    await ensureUser({ username: adminUsername, password: adminPassword, roles: ["admin"] });
    await ensureUser({ username: apiUsername, password: apiPassword, roles: ["editor"] });
}
function normalizeClientIp(raw) {
    if (!raw)
        return undefined;
    // If multiple IPs are present (x-forwarded-for), take the first
    const first = raw.split(",")[0]?.trim();
    if (!first)
        return undefined;
    // Strip IPv6-mapped IPv4 prefix (e.g. ::ffff:192.168.1.10)
    const noV6Map = first.startsWith("::ffff:") ? first.slice("::ffff:".length) : first;
    // If something includes a port like 192.168.1.10:12345, strip port
    const noPort = noV6Map.match(/^\d+\.\d+\.\d+\.\d+:/) ? noV6Map.split(":")[0] : noV6Map;
    return noPort;
}
function getClientIp(request) {
    const xff = request.headers?.["x-forwarded-for"];
    return normalizeClientIp(xff ?? request.ip);
}
async function requireAuth(request, reply) {
    try {
        await request.jwtVerify();
    }
    catch {
        reply.code(401).send({ error: "Unauthorized" });
    }
}
function requireAnyRole(roles) {
    return async (request, reply) => {
        await requireAuth(request, reply);
        if (reply.sent)
            return;
        const userRoles = request.user?.roles ?? [];
        const ok = roles.some((r) => userRoles.includes(r));
        if (!ok) {
            reply.code(403).send({ error: "Forbidden" });
        }
    };
}
function requireRole(role) {
    return requireAnyRole([role]);
}
app.get("/health", async () => {
    return { status: "ok" };
});
app.post("/auth/login", async (request, reply) => {
    const body = request.body;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");
    if (!username || !password) {
        return reply.code(400).send({ error: "Username and password required" });
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
    await users().updateOne({ _id: doc._id }, { $set: { "user.lastLoginAt": now, "user.updatedAt": now } });
    const token = await reply.jwtSign({
        sub: doc._id,
        username: doc.user.username,
        roles: doc.user.roles,
    });
    return reply.send({
        token,
        user: { username: doc.user.username, roles: doc.user.roles },
    });
});
app.post("/auth/register", async (request, reply) => {
    const body = request.body;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");
    // Optional requested role (viewer/editor only). Default to editor.
    const requestedRoleRaw = String(body?.role ?? "editor").toLowerCase();
    const role = requestedRoleRaw === "viewer" ? "viewer" : "editor";
    if (!username || !password) {
        return reply.code(400).send({ error: "Username and password required" });
    }
    // Basic sanity limits (keeps junk out of DB)
    if (username.length < 3 || username.length > 50) {
        return reply.code(400).send({ error: "Username must be 3-50 characters" });
    }
    if (password.length < 8 || password.length > 200) {
        return reply.code(400).send({ error: "Password must be at least 8 characters" });
    }
    const existing = await users().findOne({ "user.username": username }, { projection: { _id: 1 } });
    if (existing) {
        return reply.code(409).send({ error: "Username already exists" });
    }
    const now = new Date();
    const doc = {
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
    // Auto-login on register (convenient for the web portal)
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
app.get("/rooms", async (request) => {
    const { campus, building } = request.query;
    const filter = {};
    if (campus)
        filter["config.campus"] = campus;
    if (building)
        filter["config.building"] = building;
    const rooms = await roomConfigs()
        .find(filter, { projection: ROOM_SUMMARY_PROJECTION })
        .sort({ "config.campus": 1, "config.building": 1, "config.room": 1 })
        .toArray();
    return rooms;
});
app.get("/rooms/:roomId", async (request, reply) => {
    const { roomId } = request.params;
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1, config: 1 } });
    if (!room) {
        return reply.code(404).send({ error: "Room not found" });
    }
    return room;
});
app.get("/campuses/:campus/rooms", async (request) => {
    const { campus } = request.params;
    const rooms = await roomConfigs()
        .find({ "config.campus": campus }, { projection: ROOM_SUMMARY_PROJECTION })
        .sort({ "config.building": 1, "config.room": 1 })
        .toArray();
    return rooms;
});
app.get("/campuses/:campus/buildings/:building/rooms", async (request) => {
    const { campus, building } = request.params;
    const rooms = await roomConfigs()
        .find({ "config.campus": campus, "config.building": building }, { projection: ROOM_SUMMARY_PROJECTION })
        .sort({ "config.room": 1 })
        .toArray();
    return rooms;
});
app.get("/config/by-client-ip", async (request, reply) => {
    const clientIp = getClientIp(request);
    if (!clientIp) {
        return reply.code(400).send({ error: "Unable to determine client IP" });
    }
    const doc = await roomConfigs().findOne({ "config.ip": clientIp }, { projection: { _id: 1, config: 1 } });
    if (!doc) {
        return reply.code(404).send({ error: "No config found for client IP", ip: clientIp });
    }
    return doc;
});
async function upsertRoomConfig(args) {
    const { roomId, incoming, updatedBy } = args;
    // Build the stored config: keep all incoming fields, but enforce roomId + metadata
    const config = {
        ...incoming,
        roomId,
        updatedAt: new Date(),
        updatedBy
    };
    await roomConfigs().updateOne({ _id: roomId }, { $set: { _id: roomId, config } }, { upsert: true });
    return { roomId, version: incoming?.version ?? null };
}
// Create a new room config with a generated GUID (immutable identity)
app.post("/rooms", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body;
    if (body === null || body === undefined || typeof body !== "object") {
        return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }
    const incoming = body;
    const updatedBy = request.user.username;
    // Generate an immutable GUID that is NOT tied to campus/building/room naming
    const roomId = uuidv4();
    const result = await upsertRoomConfig({ roomId, incoming, updatedBy });
    return reply.code(201).send({ success: true, roomId: result.roomId, version: result.version });
});
// Backwards-compatible alias: treat PUT /rooms as create-with-guid as well
app.put("/rooms", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body;
    if (body === null || body === undefined || typeof body !== "object") {
        return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }
    const incoming = body;
    const updatedBy = request.user.username;
    const roomId = uuidv4();
    const result = await upsertRoomConfig({ roomId, incoming, updatedBy });
    return reply.code(201).send({ success: true, roomId: result.roomId, version: result.version });
});
app.put("/rooms/:roomId", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const { roomId } = request.params;
    if (typeof roomId !== "string" || roomId.trim().length === 0) {
        return reply.code(400).send({ success: false, error: "roomId must be a non-empty string" });
    }
    const body = request.body;
    if (body === null || body === undefined || typeof body !== "object") {
        return reply.code(400).send({ success: false, error: "Body must be a JSON object" });
    }
    const incoming = body;
    const updatedBy = request.user.username;
    const result = await upsertRoomConfig({ roomId, incoming, updatedBy });
    return { success: true, roomId: result.roomId, version: result.version };
});
app.delete("/rooms/:roomId", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { roomId } = request.params;
    const res = await roomConfigs().deleteOne({ _id: roomId });
    if (res.deletedCount === 0) {
        return reply.code(404).send({ error: "Room not found" });
    }
    return { success: true, roomId };
});
const start = async () => {
    await client.connect();
    db = client.db("avdb");
    // JWT auth (required for write operations)
    await app.register(jwt, {
        secret: process.env.JWT_SECRET || "dev-secret-change-me",
    });
    // Indexes (idempotent)
    // `_id` is already unique by definition; no need for a unique index on config.roomId
    await roomConfigs().createIndex({ "config.ip": 1 });
    await roomConfigs().createIndex({ "config.campus": 1, "config.building": 1, "config.room": 1 });
    // Users index (idempotent)
    await users().createIndex({ "user.username": 1 }, { unique: true });
    // Bootstrap default app users (idempotent)
    await ensureDefaultUsers();
    await app.listen({ port: 8080, host: "0.0.0.0" });
    console.log("API running on port 8080");
};
start();
