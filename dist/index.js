import Fastify from "fastify";
import jwt from "@fastify/jwt";
import cors from "@fastify/cors";
import { MongoClient } from "mongodb";
import { v4 as uuidv4 } from "uuid";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import mqtt from "mqtt";
import { exec } from "child_process";
const app = Fastify({ logger: true, bodyLimit: 10485760 }); // 10MB
// CORS (needed for browser-based clients like the Angular portal)
// Register early so preflight OPTIONS always gets the right headers.
app.register(cors, {
    origin: true, // reflect request Origin (dev-friendly)
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
});
const MONGO_URI = process.env.MONGO_URI ||
    "mongodb://avapp:avrocks@192.168.1.225:27017/avdb?authSource=avdb";
const MQTT_URL = process.env.MQTT_URL || "mqtt://localhost:1883";
const mqttClient = mqtt.connect(MQTT_URL, { clientId: "av-api", clean: true });
mqttClient.on("connect", () => app.log.info("MQTT connected"));
mqttClient.on("error", (err) => app.log.error({ err }, "MQTT error"));
const SETTINGS_ENCRYPTION_KEY = Buffer.from(process.env.SETTINGS_ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex"), "hex").slice(0, 32);
function encryptField(value) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", SETTINGS_ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return { iv: iv.toString("hex"), data: encrypted.toString("hex") };
}
function decryptField(field) {
    const iv = Buffer.from(field.iv, "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", SETTINGS_ENCRYPTION_KEY, iv);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(field.data, "hex")), decipher.final()]);
    return decrypted.toString("utf8");
}
const client = new MongoClient(MONGO_URI);
let db;
const roomConfigs = () => db.collection("rooms");
const templates = () => db.collection("templates");
const usageEvents = () => db.collection("usage");
const reports = () => db.collection("reports");
const systemSettings = () => db.collection("settings");
const roomStates = () => db.collection("state");
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
    "config.sla": 1,
    "config.slaExpireAt": 1,
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
    const { username, password, roles, mustChangePassword } = args;
    const existing = await users().findOne({ "user.username": username });
    if (existing) {
        // If the account exists but still has the default password, ensure mustChangePassword is set
        if (mustChangePassword && verifyPasswordScrypt(password, existing.user.passwordHash)) {
            await users().updateOne({ "user.username": username }, { $set: { "user.mustChangePassword": true, "user.updatedAt": new Date() } });
        }
        return;
    }
    const now = new Date();
    const doc = {
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
    app.log.info({ username, roles }, "Bootstrapped default user");
}
async function ensureDefaultUsers() {
    const adminUsername = process.env.BOOTSTRAP_ADMIN_USERNAME || "admin";
    const adminPassword = process.env.BOOTSTRAP_ADMIN_PASSWORD || "admin";
    await ensureUser({ username: adminUsername, password: adminPassword, roles: ["admin"], mustChangePassword: true });
}
async function ensureDefaultTemplates() {
    const count = await templates().countDocuments();
    if (count > 0)
        return;
    const templateDir = "/app/templates";
    try {
        const files = fs.readdirSync(templateDir).filter(f => f.endsWith(".json"));
        for (const file of files) {
            try {
                const doc = JSON.parse(fs.readFileSync(`${templateDir}/${file}`, "utf8"));
                if (doc._id)
                    await templates().insertOne(doc);
            }
            catch { /* skip malformed files */ }
        }
        app.log.info({ count: files.length }, "Seeded default templates");
    }
    catch { /* templates dir not mounted, skip */ }
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
    await users().updateOne({ _id: doc._id }, { $set: { "user.lastLoginAt": now, "user.updatedAt": now } });
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
app.patch("/auth/change-password", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const body = request.body;
    const currentPassword = String(body?.currentPassword ?? "");
    const newPassword = String(body?.newPassword ?? "");
    if (!currentPassword || !newPassword) {
        return reply.code(400).send({ error: "currentPassword and newPassword are required" });
    }
    if (newPassword.length < 8 || newPassword.length > 200) {
        return reply.code(400).send({ error: "New password must be at least 8 characters" });
    }
    const doc = await users().findOne({ _id: request.user.sub });
    if (!doc)
        return reply.code(404).send({ error: "User not found" });
    const ok = verifyPasswordScrypt(currentPassword, doc.user.passwordHash);
    if (!ok)
        return reply.code(401).send({ error: "Current password is incorrect" });
    const now = new Date();
    await users().updateOne({ _id: doc._id }, { $set: { "user.passwordHash": hashPasswordScrypt(newPassword), "user.mustChangePassword": false, "user.updatedAt": now } });
    return reply.send({ success: true });
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
// ----- Sync -----
// Tracks rooms that have a pending sync request.
// The QSys core polls GET /rooms/:roomId/sync-status and clears it once synced.
const pendingSyncs = new Set();
app.post("/rooms/:roomId/sync", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const { roomId } = request.params;
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1 } });
    if (!room)
        return reply.code(404).send({ error: "Room not found" });
    pendingSyncs.add(roomId);
    return { success: true, roomId };
});
app.get("/rooms/:roomId/sync-status", { preHandler: requireAuth }, async (request, reply) => {
    const { roomId } = request.params;
    const pending = pendingSyncs.has(roomId);
    if (pending)
        pendingSyncs.delete(roomId);
    return { roomId, syncRequested: pending };
});
// ----- Room State (pushed by Q-SYS, fanned out to MQTT) -----
app.get("/rooms/states", async () => {
    const docs = await roomStates().find({}).toArray();
    return docs;
});
app.get("/rooms/:roomId/state", async (request, reply) => {
    const { roomId } = request.params;
    const doc = await roomStates().findOne({ _id: roomId });
    if (!doc)
        return reply.code(404).send({ error: "No state found for this room" });
    return doc;
});
app.patch("/rooms/:roomId/state", async (request, reply) => {
    const { roomId } = request.params;
    const body = request.body;
    if (!body || typeof body !== "object") {
        return reply.code(400).send({ error: "Body must be a JSON object" });
    }
    // Persist state into dedicated state collection (upsert by roomId)
    await roomStates().updateOne({ _id: roomId }, { $set: { ...body, _id: roomId, updatedAt: new Date() } }, { upsert: true });
    // Publish to MQTT so portal and other subscribers get instant update
    mqttClient.publish(`av/rooms/${roomId}/state`, JSON.stringify({ roomId, ...body, updatedAt: new Date().toISOString() }), { retain: true, qos: 0 });
    return { success: true };
});
// ----- Usage / Statistics -----
// Room controller posts a batch of events (or a single event)
app.post("/rooms/:roomId/usage", async (request, reply) => {
    const { roomId } = request.params;
    const body = request.body;
    const events = Array.isArray(body) ? body : [body];
    if (events.length === 0) {
        return reply.code(400).send({ error: "No events provided" });
    }
    const now = new Date();
    const docs = events.map((e) => ({
        _id: uuidv4(),
        roomId,
        timestamp: e.timestamp ? new Date(e.timestamp) : now,
        event: String(e.event ?? "unknown"),
        payload: e.payload ?? {},
    }));
    await usageEvents().insertMany(docs);
    return reply.code(201).send({ inserted: docs.length });
});
// Query usage events for a room with optional date range
app.get("/rooms/:roomId/usage", async (request, reply) => {
    const { roomId } = request.params;
    const { from, to, event, limit } = request.query;
    const filter = { roomId };
    if (from || to) {
        const range = {};
        if (from)
            range.$gte = new Date(from);
        if (to)
            range.$lte = new Date(to);
        filter.timestamp = range;
    }
    if (event)
        filter.event = event;
    const docs = await usageEvents()
        .find(filter)
        .sort({ timestamp: -1 })
        .limit(Number(limit ?? 500))
        .toArray();
    return docs;
});
// Query usage across all rooms (for OpenClaw reporting)
app.get("/usage", async (request, _reply) => {
    const { from, to, event, roomId, limit } = request.query;
    const filter = {};
    if (roomId)
        filter.roomId = roomId;
    if (event)
        filter.event = event;
    if (from || to) {
        const range = {};
        if (from)
            range.$gte = new Date(from);
        if (to)
            range.$lte = new Date(to);
        filter.timestamp = range;
    }
    const docs = await usageEvents()
        .find(filter)
        .sort({ timestamp: -1 })
        .limit(Number(limit ?? 1000))
        .toArray();
    return docs;
});
// ----- Reports -----
app.get("/reports", async () => {
    return reports()
        .find({}, { projection: { _id: 1, title: 1, createdAt: 1, createdBy: 1 } })
        .sort({ createdAt: -1 })
        .toArray();
});
app.get("/reports/:id", async (request, reply) => {
    const { id } = request.params;
    const doc = await reports().findOne({ _id: id });
    if (!doc)
        return reply.code(404).send({ error: "Report not found" });
    return doc;
});
app.post("/reports", async (request, reply) => {
    const body = request.body;
    const title = String(body?.title ?? "").trim();
    const reportBody = String(body?.body ?? "").trim();
    const createdBy = String(body?.createdBy ?? "system").trim();
    if (!title)
        return reply.code(400).send({ error: "title is required" });
    if (!reportBody)
        return reply.code(400).send({ error: "body is required" });
    const doc = {
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
    const { id } = request.params;
    const res = await reports().deleteOne({ _id: id });
    if (res.deletedCount === 0)
        return reply.code(404).send({ error: "Report not found" });
    return { success: true };
});
// ----- Settings -----
app.post("/settings/reset-mongo-password", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { password } = request.body;
    if (!password || password.length < 6)
        return reply.code(400).send({ error: "Password must be at least 6 characters" });
    try {
        const rootUsername = process.env.MONGO_ROOT_USERNAME || "admin";
        const currentPassword = readEnvFileValue(STACK_ENV_PATH, "MONGO_ROOT_PASSWORD") || "admin";
        await new Promise((resolve, reject) => {
            exec(`docker exec av-mongo mongosh -u ${rootUsername} -p ${JSON.stringify(currentPassword)} --authenticationDatabase admin --eval ${JSON.stringify(`db.getSiblingDB('admin').updateUser('${rootUsername}', {pwd: '${password}'})`)} --quiet`, (err, _stdout, stderr) => err ? reject(new Error(stderr || err.message)) : resolve());
        });
        updateEnvFile(STACK_ENV_PATH, { MONGO_ROOT_PASSWORD: password });
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.get("/settings/status", async () => {
    const doc = await systemSettings().findOne({ _id: "system" });
    return { setupComplete: doc?.setupComplete ?? false, portalName: doc?.portalName ?? "" };
});
app.get("/settings", { preHandler: requireRole("admin") }, async (_request, reply) => {
    const doc = await systemSettings().findOne({ _id: "system" });
    if (!doc)
        return reply.code(404).send({ error: "Settings not found" });
    return {
        setupComplete: doc.setupComplete,
        portalName: doc.portalName,
        apiCredentials: doc.apiCredentials ? { username: decryptField(doc.apiCredentials.username) } : null,
        openclawCredentials: doc.openclawCredentials ? { username: decryptField(doc.openclawCredentials.username) } : null,
        openclawLlmProvider: doc.openclawLlmProvider ?? '',
        openclawLlmModel: doc.openclawLlmModel ?? '',
        openclawLlmKeySet: !!doc.openclawLlmApiKey,
        openclawModelCache: doc.openclawModelCache ?? [],
        openclawSkills: doc.openclawSkills ?? [],
        openclawChannels: (doc.openclawChannels ?? []).map(c => ({
            name: c.name,
            tokenSet: !!c.token,
        })),
        mqttCredentials: doc.mqttCredentials ? { username: decryptField(doc.mqttCredentials.username) } : null,
        dbCredentials: doc.dbCredentials ? { username: decryptField(doc.dbCredentials.username) } : null,
    };
});
app.put("/settings", { preHandler: requireRole("admin") }, async (request, _reply) => {
    const body = request.body;
    const now = new Date();
    const update = {
        updatedAt: now,
        updatedBy: request.user.username,
    };
    if (body.portalName !== undefined)
        update.portalName = body.portalName;
    if (body.setupComplete !== undefined)
        update.setupComplete = body.setupComplete;
    if (body.apiCredentials?.username)
        update.apiCredentials = {
            username: encryptField(body.apiCredentials.username),
            password: encryptField(body.apiCredentials.password),
        };
    if (body.anthropicApiKey)
        update.anthropicApiKey = encryptField(body.anthropicApiKey);
    if (body.openclawCredentials?.username)
        update.openclawCredentials = {
            username: encryptField(body.openclawCredentials.username),
            password: encryptField(body.openclawCredentials.password),
        };
    if (body.openclawLlmProvider !== undefined)
        update.openclawLlmProvider = body.openclawLlmProvider;
    if (body.openclawLlmModel !== undefined)
        update.openclawLlmModel = body.openclawLlmModel;
    if (Array.isArray(body.openclawSkills))
        update.openclawSkills = body.openclawSkills;
    if (Array.isArray(body.openclawChannels)) {
        update.openclawChannels = body.openclawChannels.map((c) => ({
            name: c.name,
            token: encryptField(c.token ?? ''),
        }));
    }
    if (body.mqttCredentials?.username)
        update.mqttCredentials = {
            username: encryptField(body.mqttCredentials.username),
            password: encryptField(body.mqttCredentials.password),
        };
    if (body.dbCredentials?.username)
        update.dbCredentials = {
            username: encryptField(body.dbCredentials.username),
            password: encryptField(body.dbCredentials.password),
        };
    await systemSettings().updateOne({ _id: "system" }, { $set: update }, { upsert: true });
    return { success: true };
});
const STACK_ENV_PATH = process.env.STACK_ENV_PATH || "/run/secrets/stack.env";
function readEnvFileValue(path, key) {
    try {
        const content = fs.readFileSync(path, "utf8");
        const line = content.split("\n").find(l => l.startsWith(`${key}=`) || l.startsWith(`${key} =`));
        if (!line)
            return "";
        return line.split("=").slice(1).join("=").replace(/^["']|["']$/g, "").trim();
    }
    catch {
        return "";
    }
}
function updateEnvFile(path, updates) {
    let content = "";
    try {
        content = fs.readFileSync(path, "utf8");
    }
    catch { /* file may not exist */ }
    const lines = content.split("\n");
    for (const [key, value] of Object.entries(updates)) {
        const escaped = value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
        const newLine = `${key}="${escaped}"`;
        const idx = lines.findIndex(l => l.startsWith(`${key}=`) || l.startsWith(`${key} =`));
        if (idx >= 0)
            lines[idx] = newLine;
        else
            lines.push(newLine);
    }
    fs.writeFileSync(path, lines.filter((l, i) => l !== "" || i === lines.length - 1).join("\n"), "utf8");
}
app.post("/openclaw/configure-db-credentials", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");
    if (!username || !password)
        return reply.code(400).send({ error: "Username and password are required" });
    try {
        updateEnvFile(STACK_ENV_PATH, {
            OPENCLAW_API_USERNAME: username,
            OPENCLAW_API_PASSWORD: password,
        });
        await new Promise((resolve, reject) => exec(`docker compose -p av -f /run/secrets/docker-compose.yml --env-file /run/secrets/stack.env up -d --no-deps openclaw`, (err) => err ? reject(err) : resolve()));
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
// Endpoint for OpenClaw to fetch its own API key
app.get("/settings/openclaw-key", { preHandler: requireRole("admin") }, async (_request, reply) => {
    const doc = await systemSettings().findOne({ _id: "system" });
    if (!doc?.anthropicApiKey)
        return reply.code(404).send({ error: "Anthropic API key not configured" });
    return { apiKey: decryptField(doc.anthropicApiKey) };
});
// ----- OpenClaw management -----
const OPENCLAW_CONTAINER = process.env.OPENCLAW_CONTAINER || "av-openclaw";
function runInContainer(cmd) {
    return new Promise((resolve, reject) => {
        exec(`docker exec ${OPENCLAW_CONTAINER} sh -c ${JSON.stringify(cmd)}`, (err, stdout, stderr) => {
            if (err)
                reject(new Error(stderr || err.message));
            else
                resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
        });
    });
}
// Provider map: portal LLM value -> openclaw provider id + default model
const LLM_PROVIDER_MAP = {
    anthropic: { provider: "anthropic", model: "anthropic/claude-sonnet-4-5" },
    openai: { provider: "openai", model: "openai/gpt-4o" },
    google: { provider: "google", model: "google/gemini-2.5-flash" },
};
const OPENCLAW_MODELS = [
    "anthropic/claude-3-5-haiku-20241022", "anthropic/claude-3-5-haiku-latest", "anthropic/claude-3-5-sonnet-20240620",
    "anthropic/claude-3-5-sonnet-20241022", "anthropic/claude-3-7-sonnet-20250219", "anthropic/claude-3-haiku-20240307",
    "anthropic/claude-3-opus-20240229", "anthropic/claude-3-sonnet-20240229", "anthropic/claude-haiku-4-5",
    "anthropic/claude-haiku-4-5-20251001", "anthropic/claude-opus-4-0", "anthropic/claude-opus-4-1",
    "anthropic/claude-opus-4-1-20250805", "anthropic/claude-opus-4-20250514", "anthropic/claude-opus-4-5",
    "anthropic/claude-opus-4-5-20251101", "anthropic/claude-opus-4-6", "anthropic/claude-opus-4-7",
    "anthropic/claude-sonnet-4-0", "anthropic/claude-sonnet-4-20250514", "anthropic/claude-sonnet-4-5",
    "anthropic/claude-sonnet-4-5-20250929", "anthropic/claude-sonnet-4-6",
    "google/gemini-1.5-flash", "google/gemini-1.5-flash-8b", "google/gemini-1.5-pro",
    "google/gemini-2.0-flash", "google/gemini-2.0-flash-lite", "google/gemini-2.5-flash",
    "google/gemini-2.5-flash-lite", "google/gemini-2.5-flash-lite-preview-06-17", "google/gemini-2.5-flash-lite-preview-09-2025",
    "google/gemini-2.5-flash-preview-04-17", "google/gemini-2.5-flash-preview-05-20", "google/gemini-2.5-flash-preview-09-2025",
    "google/gemini-2.5-pro", "google/gemini-2.5-pro-preview-05-06", "google/gemini-2.5-pro-preview-06-05",
    "google/gemini-3-flash-preview", "google/gemini-3-pro-preview", "google/gemini-3.1-flash-lite-preview",
    "google/gemini-3.1-pro-preview", "google/gemini-3.1-pro-preview-customtools", "google/gemini-flash-latest",
    "google/gemini-flash-lite-latest", "google/gemini-live-2.5-flash", "google/gemini-live-2.5-flash-preview-native-audio",
    "google/gemma-3-27b-it", "google/gemma-4-26b-it", "google/gemma-4-31b-it",
    "openai/gpt-4", "openai/gpt-4-turbo", "openai/gpt-4.1", "openai/gpt-4.1-mini", "openai/gpt-4.1-nano",
    "openai/gpt-4o", "openai/gpt-4o-2024-05-13", "openai/gpt-4o-2024-08-06", "openai/gpt-4o-2024-11-20", "openai/gpt-4o-mini",
    "openai/gpt-5", "openai/gpt-5-chat-latest", "openai/gpt-5-codex", "openai/gpt-5-mini", "openai/gpt-5-nano", "openai/gpt-5-pro",
    "openai/gpt-5.1", "openai/gpt-5.1-chat-latest", "openai/gpt-5.1-codex", "openai/gpt-5.1-codex-max", "openai/gpt-5.1-codex-mini",
    "openai/gpt-5.2", "openai/gpt-5.2-chat-latest", "openai/gpt-5.2-codex", "openai/gpt-5.2-pro",
    "openai/gpt-5.3-chat-latest", "openai/gpt-5.3-codex", "openai/gpt-5.4", "openai/gpt-5.4-mini", "openai/gpt-5.4-nano", "openai/gpt-5.4-pro",
    "openai/o1", "openai/o1-pro", "openai/o3", "openai/o3-deep-research", "openai/o3-mini", "openai/o3-pro",
    "openai/o4-mini", "openai/o4-mini-deep-research",
];
app.get("/openclaw/status", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
        const { stdout } = await runInContainer("openclaw gateway health --json 2>/dev/null || echo '{\"running\":false}'");
        let health = { running: false };
        try {
            health = JSON.parse(stdout);
            health.running = true;
        }
        catch { /* not running */ }
        return { running: health.running, health };
    }
    catch {
        return { running: false };
    }
});
app.post("/openclaw/start", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
        // Send SIGCONT or just check — the container process is managed by docker restart policy.
        // We restart the container to bring it back up if it exited.
        await new Promise((resolve, reject) => exec(`docker restart ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve()));
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.post("/openclaw/stop", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
        await new Promise((resolve, reject) => exec(`docker stop ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve()));
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.get("/openclaw/models", { preHandler: requireRole("admin") }, async () => {
    try {
        const { stdout } = await runInContainer(`openclaw models list --all --json 2>/dev/null | node -e "const d=require('fs').readFileSync('/dev/stdin','utf8'); const j=JSON.parse(d); const m=j.models.filter(m=>m.key.startsWith('anthropic/')||m.key.startsWith('openai/')||m.key.startsWith('google/')).map(m=>m.key); process.stdout.write(JSON.stringify(m));"`);
        const live = JSON.parse(stdout);
        if (live.length > 0) {
            // Cache in DB for offline fallback
            await systemSettings().updateOne({ _id: "system" }, { $set: { openclawModelCache: live } }, { upsert: true });
            return live;
        }
    }
    catch { /* openclaw not running — fall through */ }
    // Fallback: cached list from DB, then hardcoded
    const doc = await systemSettings().findOne({ _id: "system" });
    return doc?.openclawModelCache ?? OPENCLAW_MODELS;
});
app.get("/openclaw/active-model", { preHandler: requireRole("admin") }, async () => {
    try {
        const { stdout } = await runInContainer("openclaw models list 2>/dev/null | grep default | awk '{print $1}'");
        return { model: stdout.trim() };
    }
    catch {
        return { model: '' };
    }
});
app.post("/openclaw/configure-llm", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body;
    const llm = String(body?.llmProvider ?? "");
    const apiKey = String(body?.apiKey ?? "");
    const model = String(body?.model ?? "");
    const baseUrl = body?.baseUrl ? String(body.baseUrl).trim() : "";
    const mapping = LLM_PROVIDER_MAP[llm];
    if (!llm || !mapping)
        return reply.code(400).send({ error: "Invalid LLM provider" });
    const targetModel = model || mapping.model;
    try {
        if (apiKey) {
            const profilesPath = "/root/.openclaw/agents/main/agent/auth-profiles.json";
            // Write auth profile directly — openclaw's paste-token stdin is unreliable in non-interactive mode
            await runInContainer(`node -e "
        const fs = require('fs');
        let data = { version: 1, profiles: {} };
        try { data = JSON.parse(fs.readFileSync(${JSON.stringify(profilesPath)}, 'utf8')); } catch {}
        data.profiles[${JSON.stringify(mapping.provider + ':manual')}] = {
          type: 'token', provider: ${JSON.stringify(mapping.provider)}, token: ${JSON.stringify(apiKey)}
        };
        fs.writeFileSync(${JSON.stringify(profilesPath)}, JSON.stringify(data, null, 2));
      "`);
            // If a custom base URL is provided, configure a custom provider in openclaw.json
            if (baseUrl) {
                const configPath = "/root/.openclaw/openclaw.json";
                await runInContainer(`node -e "
          const fs = require('fs');
          let cfg = {};
          try { cfg = JSON.parse(fs.readFileSync(${JSON.stringify(configPath)}, 'utf8')); } catch {}
          cfg.providers = cfg.providers || {};
          cfg.providers[${JSON.stringify(mapping.provider)}] = { baseUrl: ${JSON.stringify(baseUrl)}, apiKey: ${JSON.stringify(apiKey)} };
          fs.writeFileSync(${JSON.stringify(configPath)}, JSON.stringify(cfg, null, 2));
        "`);
            }
            // Restart so the gateway reloads the new auth profile
            await new Promise((resolve, reject) => exec(`docker restart ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve()));
            // Wait for the gateway to come back up before setting the model
            await new Promise(r => setTimeout(r, 5000));
        }
        // Set the default model (after restart if key was saved)
        await runInContainer(`openclaw models set ${targetModel}`);
        // Clear sessions so the next message starts fresh with the new model
        await runInContainer("rm -f /root/.openclaw/agents/main/sessions/sessions.json");
        // Persist to DB
        const dbUpdate = { openclawLlmProvider: llm, openclawLlmModel: targetModel, updatedAt: new Date(), updatedBy: request.user.username };
        if (apiKey)
            dbUpdate.openclawLlmApiKey = encryptField(apiKey);
        if (baseUrl)
            dbUpdate.openclawBaseUrl = baseUrl;
        await systemSettings().updateOne({ _id: "system" }, { $set: dbUpdate });
        return { success: true, model: targetModel };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
const CHANNEL_TOKEN_FLAG = {
    discord: "--token",
    slack: "--bot-token",
    telegram: "--token",
};
app.post("/openclaw/configure-channel", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body;
    const channel = String(body?.channel ?? "").toLowerCase();
    const token = String(body?.token ?? "");
    if (!channel)
        return reply.code(400).send({ error: "channel is required" });
    if (!token)
        return reply.code(400).send({ error: "token is required" });
    const tokenFlag = CHANNEL_TOKEN_FLAG[channel];
    if (!tokenFlag)
        return reply.code(400).send({ error: `Unsupported channel: ${channel}` });
    try {
        await runInContainer(`openclaw channels add --channel ${channel} ${tokenFlag} ${JSON.stringify(token)}`);
        // Persist token encrypted in DB
        const doc = await systemSettings().findOne({ _id: "system" });
        const channels = (doc?.openclawChannels ?? []).filter(c => c.name !== channel);
        channels.push({ name: channel, token: encryptField(token) });
        await systemSettings().updateOne({ _id: "system" }, { $set: { openclawChannels: channels } });
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.delete("/openclaw/configure-channel/:channel", { preHandler: requireRole("admin") }, async (request, reply) => {
    const channel = request.params.channel;
    try {
        await runInContainer(`openclaw channels remove --channel ${channel}`);
        const doc = await systemSettings().findOne({ _id: "system" });
        const channels = (doc?.openclawChannels ?? []).filter(c => c.name !== channel);
        await systemSettings().updateOne({ _id: "system" }, { $set: { openclawChannels: channels } });
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.get("/openclaw/skills", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
        const { stdout } = await runInContainer("openclaw skills list --json 2>/dev/null");
        const data = JSON.parse(stdout);
        // Get the current allowlist (null = unrestricted = all enabled)
        let allowlist = null;
        try {
            const { stdout: cfg } = await runInContainer("openclaw config get agents.defaults.skills --json 2>/dev/null || echo 'null'");
            const parsed = JSON.parse(cfg);
            if (Array.isArray(parsed))
                allowlist = parsed;
        }
        catch { /* no allowlist set */ }
        const skills = data.skills
            .filter(s => s.source === "openclaw-workspace")
            .map(s => ({
            name: s.name,
            description: s.description,
            eligible: s.eligible,
            enabled: allowlist === null ? true : allowlist.includes(s.name),
        }));
        return { skills, allowlist };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.put("/openclaw/skills", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body;
    const enabled = Array.isArray(body?.enabled) ? body.enabled : [];
    try {
        // Set the allowlist — empty array means no skills, populated means only those skills
        await runInContainer(`openclaw config set agents.defaults.skills --strict-json ${JSON.stringify(JSON.stringify(enabled))}`);
        // Persist to DB as well
        await systemSettings().updateOne({ _id: "system" }, { $set: { openclawSkills: enabled, updatedAt: new Date() } });
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.get("/openclaw/pairing", { preHandler: requireRole("admin") }, async () => {
    try {
        const { stdout } = await runInContainer("openclaw pairing list --json 2>/dev/null || echo '{}'");
        try {
            const parsed = JSON.parse(stdout);
            return Array.isArray(parsed.requests) ? parsed.requests : [];
        }
        catch {
            return [];
        }
    }
    catch {
        return [];
    }
});
app.get("/openclaw/pairing/approved", { preHandler: requireRole("admin") }, async () => {
    try {
        const { stdout } = await runInContainer("openclaw pairing list --json 2>/dev/null || echo '{}'");
        try {
            const parsed = JSON.parse(stdout);
            return Array.isArray(parsed.approved) ? parsed.approved : [];
        }
        catch {
            return [];
        }
    }
    catch {
        return [];
    }
});
app.post("/openclaw/pairing/approve", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body;
    const code = String(body?.code ?? "").trim();
    const channel = String(body?.channel ?? "discord");
    if (!code)
        return reply.code(400).send({ error: "code is required" });
    try {
        await runInContainer(`openclaw pairing approve --channel ${channel} --notify ${code}`);
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.post("/openclaw/pairing/revoke", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { channel, id } = request.body;
    if (!channel || !id)
        return reply.code(400).send({ error: "channel and id required" });
    try {
        await runInContainer(`openclaw pairing revoke --channel ${channel} --user ${id} 2>&1`);
        return { success: true };
    }
    catch (err) {
        return reply.code(500).send({ error: err.message });
    }
});
app.get("/openclaw/dashboard-url", { preHandler: requireRole("admin") }, async (request, reply) => {
    try {
        const { stdout } = await runInContainer("openclaw dashboard --no-open 2>&1 | grep 'Dashboard URL:' | sed 's/.*Dashboard URL: //'");
        // Rewrite the host to match what the browser used to reach the portal,
        // so the link works on any machine (local or remote Pi).
        const host = (request.headers["host"] ?? "localhost:8080").split(":")[0];
        return { url: stdout.trim().replace("127.0.0.1", host) };
    }
    catch {
        return reply.code(503).send({ error: "OpenClaw is not running" });
    }
});
// ----- Streams -----
const MEDIAMTX_HOST = process.env.MEDIAMTX_HOST || "192.168.1.225";
const MEDIAMTX_WEBRTC_PORT = process.env.MEDIAMTX_WEBRTC_PORT || "8889";
const MEDIAMTX_HLS_PORT = process.env.MEDIAMTX_HLS_PORT || "8888";
app.get("/rooms/:roomId/streams", async (request, reply) => {
    const { roomId } = request.params;
    const room = await roomConfigs().findOne({ _id: roomId }, { projection: { _id: 1, config: 1 } });
    if (!room) {
        return reply.code(404).send({ error: "Room not found" });
    }
    const devices = (room.config.Devices ?? {});
    const streams = [];
    for (const [key, device] of Object.entries(devices)) {
        const rtspUrl = device.RtspUrl;
        if (!rtspUrl)
            continue;
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
app.post("/templates", { preHandler: requireAnyRole(["admin", "editor"]) }, async (request, reply) => {
    const body = request.body;
    if (!body?.name)
        return reply.code(400).send({ error: "name is required" });
    const doc = {
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
app.get("/templates", async () => {
    return templates()
        .find({}, { projection: { _id: 1, name: 1, icon: 1, createdby: 1, created: 1, permission: 1 } })
        .sort({ name: 1 })
        .toArray();
});
app.get("/templates/:id", async (request, reply) => {
    const { id } = request.params;
    const doc = await templates().findOne({ _id: id });
    if (!doc) {
        return reply.code(404).send({ error: "Template not found" });
    }
    return doc;
});
app.patch("/templates/:id", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const { id } = request.params;
    const body = request.body;
    const isAdmin = request.user.roles.includes("admin");
    const doc = await templates().findOne({ _id: id });
    if (!doc)
        return reply.code(404).send({ error: "Template not found" });
    // Non-admins can only edit their own templates, and cannot change permission
    if (!isAdmin) {
        if (doc.createdby !== request.user.username) {
            return reply.code(403).send({ error: "Not authorized to edit this template" });
        }
        if (body.permission !== undefined) {
            return reply.code(403).send({ error: "Only admins can change template permission" });
        }
    }
    const update = {};
    if (body.name !== undefined)
        update.name = body.name;
    if (body.permission !== undefined)
        update.permission = body.permission;
    if (body.config !== undefined)
        update.config = body.config;
    if (Object.keys(update).length === 0)
        return reply.code(400).send({ error: "Nothing to update" });
    await templates().updateOne({ _id: id }, { $set: update });
    return { success: true };
});
app.delete("/templates/:id", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const { id } = request.params;
    const isAdmin = request.user.roles.includes("admin");
    const doc = await templates().findOne({ _id: id });
    if (!doc)
        return reply.code(404).send({ error: "Template not found" });
    if (!isAdmin && doc.createdby !== request.user.username) {
        return reply.code(403).send({ error: "Not authorized to delete this template" });
    }
    if (!isAdmin && doc.permission === "admin") {
        return reply.code(403).send({ error: "This template has been promoted to admin-only and cannot be deleted by its creator" });
    }
    await templates().deleteOne({ _id: id });
    return { success: true };
});
// ── Self-service profile ──────────────────────────────────────────────────────
app.patch("/auth/me/username", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const body = request.body;
    const username = String(body?.username ?? "").trim();
    if (!username || username.length < 3 || username.length > 50) {
        return reply.code(400).send({ error: "Username must be 3-50 characters" });
    }
    const existing = await users().findOne({ "user.username": username }, { projection: { _id: 1 } });
    if (existing && existing._id !== request.user.sub) {
        return reply.code(409).send({ error: "Username already taken" });
    }
    const res = await users().updateOne({ _id: request.user.sub }, { $set: { "user.username": username, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    const token = await reply.jwtSign({ sub: request.user.sub, username, roles: request.user.roles });
    return reply.send({ token, user: { username, roles: request.user.roles } });
});
app.patch("/auth/me/password", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request, reply) => {
    const body = request.body;
    const password = String(body?.password ?? "");
    if (!password || password.length < 8 || password.length > 200) {
        return reply.code(400).send({ error: "Password must be at least 8 characters" });
    }
    const passwordHash = hashPasswordScrypt(password);
    const res = await users().updateOne({ _id: request.user.sub }, { $set: { "user.passwordHash": passwordHash, "user.mustChangePassword": false, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.get("/templates/mine", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async (request) => {
    return templates()
        .find({ createdby: request.user.username }, { projection: { _id: 1, name: 1, icon: 1, createdby: 1, created: 1, permission: 1 } })
        .toArray();
});
// ── Admin: User Management ───────────────────────────────────────────────────
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
        },
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
    const { id } = request.params;
    const body = request.body;
    const roles = body?.roles;
    const validRoles = ["admin", "editor", "viewer"];
    if (!Array.isArray(roles) || roles.length === 0 || roles.some((r) => !validRoles.includes(r))) {
        return reply.code(400).send({ error: "roles must be a non-empty array of admin|editor|viewer" });
    }
    const res = await users().updateOne({ _id: id }, { $set: { "user.roles": roles, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.patch("/admin/users/:id/username", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params;
    const body = request.body;
    const username = String(body?.username ?? "").trim();
    if (!username || username.length < 3 || username.length > 50) {
        return reply.code(400).send({ error: "Username must be 3-50 characters" });
    }
    const existing = await users().findOne({ "user.username": username }, { projection: { _id: 1 } });
    if (existing && existing._id !== id) {
        return reply.code(409).send({ error: "Username already taken" });
    }
    const res = await users().updateOne({ _id: id }, { $set: { "user.username": username, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.patch("/admin/users/:id/password", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params;
    const body = request.body;
    const password = String(body?.password ?? "");
    if (!password || password.length < 8 || password.length > 200) {
        return reply.code(400).send({ error: "Password must be at least 8 characters" });
    }
    const passwordHash = hashPasswordScrypt(password);
    const res = await users().updateOne({ _id: id }, { $set: { "user.passwordHash": passwordHash, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.patch("/admin/users/:id/active", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params;
    const body = request.body;
    if (typeof body?.isActive !== "boolean") {
        return reply.code(400).send({ error: "isActive must be a boolean" });
    }
    const res = await users().updateOne({ _id: id }, { $set: { "user.isActive": body.isActive, "user.updatedAt": new Date() } });
    if (res.matchedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.delete("/admin/users/:id", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { id } = request.params;
    const user = await users().findOne({ _id: id }, { projection: { "user.username": 1 } });
    if (!user)
        return reply.code(404).send({ error: "User not found" });
    const username = user.user?.username;
    if (username === "admin") {
        return reply.code(403).send({ error: "Cannot delete the built-in admin account" });
    }
    const res = await users().deleteOne({ _id: id });
    if (res.deletedCount === 0)
        return reply.code(404).send({ error: "User not found" });
    return { success: true };
});
app.delete("/rooms/:roomId", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { roomId } = request.params;
    const res = await roomConfigs().deleteOne({ _id: roomId });
    if (res.deletedCount === 0) {
        return reply.code(404).send({ error: "Room not found" });
    }
    return { success: true, roomId };
});
// ── Scheduler ────────────────────────────────────────────────────────────────
const SCHEDULER_SCRIPTS_DIR = "/scheduler/scripts";
const SCHEDULER_JOBS_FILE = "/scheduler/jobs.yaml";
function readJobsFile() {
    try {
        const content = fs.readFileSync(SCHEDULER_JOBS_FILE, "utf8");
        const parsed = yaml.load(content) || { jobs: [] };
        parsed.jobs = (parsed.jobs || []).map((j) => ({ enabled: true, ...j }));
        return parsed;
    }
    catch {
        return { jobs: [] };
    }
}
function writeJobsFile(config) {
    fs.writeFileSync(SCHEDULER_JOBS_FILE, yaml.dump(config), "utf8");
}
async function reloadScheduler() {
    // Send SIGHUP to the scheduler container process to reload jobs.yaml
    const { execSync } = require("child_process");
    execSync(`docker kill --signal=SIGHUP av-scheduler`);
}
app.get("/scheduler/jobs", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async () => {
    return readJobsFile();
});
app.post("/scheduler/jobs", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name, script, cron, code } = request.body;
    if (!name || !script || !cron || !code) {
        return reply.code(400).send({ error: "name, script, cron, and code are required" });
    }
    if (!/^[a-z0-9_-]+$/.test(name)) {
        return reply.code(400).send({ error: "name must be lowercase alphanumeric with hyphens/underscores" });
    }
    if (!/^[a-z0-9_-]+\.py$/.test(script)) {
        return reply.code(400).send({ error: "script must be a .py filename" });
    }
    const scriptPath = path.join(SCHEDULER_SCRIPTS_DIR, script);
    fs.writeFileSync(scriptPath, code, "utf8");
    const config = readJobsFile();
    const existing = config.jobs.findIndex(j => j.name === name);
    if (existing >= 0) {
        config.jobs[existing] = { ...config.jobs[existing], name, script, cron };
    }
    else {
        config.jobs.push({ name, script, cron, enabled: true });
    }
    writeJobsFile(config);
    try {
        await reloadScheduler();
    }
    catch { /* scheduler may not be running */ }
    return { success: true, name, script, cron };
});
app.patch("/scheduler/jobs/:name", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name } = request.params;
    const { enabled } = request.body;
    if (typeof enabled !== "boolean") {
        return reply.code(400).send({ error: "enabled must be a boolean" });
    }
    const config = readJobsFile();
    const job = config.jobs.find(j => j.name === name);
    if (!job)
        return reply.code(404).send({ error: "Job not found" });
    job.enabled = enabled;
    writeJobsFile(config);
    try {
        await reloadScheduler();
    }
    catch { /* scheduler may not be running */ }
    return { success: true };
});
app.delete("/scheduler/jobs/:name", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name } = request.params;
    const config = readJobsFile();
    const job = config.jobs.find(j => j.name === name);
    if (!job)
        return reply.code(404).send({ error: "Job not found" });
    config.jobs = config.jobs.filter(j => j.name !== name);
    writeJobsFile(config);
    const scriptPath = path.join(SCHEDULER_SCRIPTS_DIR, job.script);
    if (fs.existsSync(scriptPath))
        fs.unlinkSync(scriptPath);
    try {
        await reloadScheduler();
    }
    catch { /* scheduler may not be running */ }
    return { success: true };
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
    // Templates index (idempotent — _id is the template name)
    await templates().createIndex({ _id: 1 });
    // Usage index
    await usageEvents().createIndex({ roomId: 1, timestamp: -1 });
    await usageEvents().createIndex({ timestamp: -1 });
    // Reports index
    await reports().createIndex({ createdAt: -1 });
    // Seed default settings document if not present
    const existingSettings = await systemSettings().findOne({ _id: "system" });
    if (!existingSettings) {
        const placeholder = encryptField("not-configured");
        await systemSettings().insertOne({
            _id: "system",
            setupComplete: false,
            portalName: "AV Portal",
            apiCredentials: { username: placeholder, password: placeholder },
            anthropicApiKey: placeholder,
            openclawCredentials: { username: placeholder, password: placeholder },
            openclawLlmProvider: '',
            openclawLlmModel: '',
            openclawLlmApiKey: placeholder,
            openclawSkills: [],
            openclawChannels: [],
            mqttCredentials: { username: placeholder, password: placeholder },
            dbCredentials: { username: placeholder, password: placeholder },
            updatedAt: new Date(),
            updatedBy: "system",
        });
        app.log.info("Seeded default settings document");
    }
    // Bootstrap default app users (idempotent)
    await ensureDefaultUsers();
    // Seed default templates from /app/templates if collection is empty
    await ensureDefaultTemplates();
    await app.listen({ port: 8080, host: "0.0.0.0" });
    console.log("API running on port 8080");
};
start();
