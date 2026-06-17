import { exec } from "child_process";
import type { FastifyInstance } from "fastify";
import { systemSettings } from "../db.js";
import { encryptField } from "../crypto.js";
import { requireRole } from "../auth.js";
import { updateEnvFile, STACK_ENV_PATH } from "./settings.js";
import type { OpenclawChannel } from "../types.js";

const OPENCLAW_CONTAINER = process.env.OPENCLAW_CONTAINER || "av-openclaw";

function runInContainer(cmd: string): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    exec(`docker exec ${OPENCLAW_CONTAINER} sh -c ${JSON.stringify(cmd)}`, (err, stdout, stderr) => {
      if (err) reject(new Error(stderr || err.message));
      else resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}

const LLM_PROVIDER_MAP: Record<string, { provider: string; model: string }> = {
  anthropic: { provider: "anthropic", model: "anthropic/claude-sonnet-4-5" },
  openai:    { provider: "openai",    model: "openai/gpt-4o" },
  google:    { provider: "google",    model: "google/gemini-2.5-flash" },
  custom:    { provider: "apigee-openai",  model: "apigee-openai/gpt-4.1-mini" },
};

const CHANNEL_TOKEN_FLAG: Record<string, string> = {
  discord: "--token",
  slack: "--bot-token",
  telegram: "--token",
};

const OPENCLAW_MODELS = [
  "openai/gpt-4o",
  "openai/gpt-4o-mini",
  "openai/gpt-4.1",
  "openai/gpt-4.1-mini",
  "openai/gpt-4.1-nano",
  "openai/o1",
  "openai/o3",
  "openai/o3-mini",
  "openai/o4-mini",
];

export async function openclawRoutes(app: FastifyInstance) {
  app.get("/openclaw/status", { preHandler: requireRole("admin") }, async () => {
    try {
      const { stdout } = await runInContainer("openclaw gateway health --json 2>/dev/null || echo '{\"running\":false}'");
      let health: any = { running: false };
      try { health = JSON.parse(stdout); health.running = true; } catch { /* not running */ }
      return { running: health.running, health };
    } catch {
      return { running: false };
    }
  });

  app.post("/openclaw/start", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
      await new Promise<void>((resolve, reject) =>
        exec(`docker restart ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve())
      );
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.post("/openclaw/stop", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
      await new Promise<void>((resolve, reject) =>
        exec(`docker stop ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve())
      );
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/openclaw/models", { preHandler: requireRole("admin") }, async () => {
    try {
      const { stdout } = await runInContainer(
        `openclaw models list --all --json 2>/dev/null | node -e "const d=require('fs').readFileSync('/dev/stdin','utf8'); const j=JSON.parse(d); const m=j.models.filter(m=>m.key.startsWith('anthropic/')||m.key.startsWith('openai/')||m.key.startsWith('google/')).map(m=>m.key); process.stdout.write(JSON.stringify(m));"`
      );
      const live = JSON.parse(stdout) as string[];
      if (live.length > 0) {
        await systemSettings().updateOne({ _id: "system" }, { $set: { openclawModelCache: live } }, { upsert: true });
        return live;
      }
    } catch { /* openclaw not running — fall through */ }

    const doc = await systemSettings().findOne({ _id: "system" }) as any;
    return (doc?.openclawModelCache as string[] | undefined) ?? OPENCLAW_MODELS;
  });

  app.get("/openclaw/active-model", { preHandler: requireRole("admin") }, async () => {
    try {
      const { stdout } = await runInContainer("openclaw models list 2>/dev/null | grep default | awk '{print $1}'");
      return { model: stdout.trim() };
    } catch {
      return { model: "" };
    }
  });

  app.post("/openclaw/configure-llm", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body as any;
    const llm = String(body?.llmProvider ?? "");
    const apiKey = String(body?.apiKey ?? "");
    const model = String(body?.model ?? "");
    const baseUrl = body?.baseUrl ? String(body.baseUrl).trim() : "";

    const mapping = LLM_PROVIDER_MAP[llm];
    if (!llm || !mapping) return reply.code(400).send({ error: "Invalid LLM provider" });

    const targetModel = model || mapping.model;

    try {
      if (apiKey) {
        const profilesPath = "/root/.openclaw/agents/main/agent/auth-profiles.json";
        await runInContainer(`node -e "
          const fs = require('fs');
          let data = { version: 1, profiles: {} };
          try { data = JSON.parse(fs.readFileSync(${JSON.stringify(profilesPath)}, 'utf8')); } catch {}
          data.profiles[${JSON.stringify(mapping.provider + ':manual')}] = {
            type: 'token', provider: ${JSON.stringify(mapping.provider)}, token: ${JSON.stringify(apiKey)}
          };
          fs.writeFileSync(${JSON.stringify(profilesPath)}, JSON.stringify(data, null, 2));
        "`);

        if (baseUrl) {
          const configPath = "/root/.openclaw/openclaw.json";
          await runInContainer(`node -e "
            const fs = require('fs');
            let cfg = {};
            try { cfg = JSON.parse(fs.readFileSync(${JSON.stringify(configPath)}, 'utf8')); } catch {}
            cfg.models = cfg.models || {};
            cfg.models.mode = 'merge';
            cfg.models.providers = cfg.models.providers || {};
            cfg.models.providers[${JSON.stringify(mapping.provider)}] = {
              baseUrl: ${JSON.stringify(baseUrl)},
              apiKey: ${JSON.stringify(apiKey)},
              api: 'openai-completions',
              models: [
                {
                  id: 'gpt-4.1-mini',
                  name: 'GPT-4.1 Mini via Apigee',
                  reasoning: false,
                  input: ['text'],
                  cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
                  contextWindow: 128000,
                  contextTokens: 96000,
                  maxTokens: 32000
                }
              ]
            };
            fs.writeFileSync(${JSON.stringify(configPath)}, JSON.stringify(cfg, null, 2));
          "`);
        }

        await new Promise<void>((resolve, reject) =>
          exec(`docker restart ${OPENCLAW_CONTAINER}`, (err) => err ? reject(err) : resolve())
        );
        // Wait for the gateway to come back up before setting the model
        await new Promise(r => setTimeout(r, 5000));
      }

      await runInContainer(`openclaw models set ${targetModel}`);
      await runInContainer("rm -f /root/.openclaw/agents/main/sessions/sessions.json");

      const dbUpdate: any = { openclawLlmProvider: llm, openclawLlmModel: targetModel, updatedAt: new Date(), updatedBy: request.user.username };
      if (apiKey) dbUpdate.openclawLlmApiKey = encryptField(apiKey);
      if (baseUrl) dbUpdate.openclawBaseUrl = baseUrl;
      await systemSettings().updateOne({ _id: "system" }, { $set: dbUpdate });

      return { success: true, model: targetModel };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.post("/openclaw/configure-channel", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body as any;
    const channel = String(body?.channel ?? "").toLowerCase();
    const token = String(body?.token ?? "");

    if (!channel) return reply.code(400).send({ error: "channel is required" });
    if (!token) return reply.code(400).send({ error: "token is required" });

    const tokenFlag = CHANNEL_TOKEN_FLAG[channel];
    if (!tokenFlag) return reply.code(400).send({ error: `Unsupported channel: ${channel}` });

    try {
      await runInContainer(`openclaw channels add --channel ${channel} ${tokenFlag} ${JSON.stringify(token)}`);
      const doc = await systemSettings().findOne({ _id: "system" });
      const channels: OpenclawChannel[] = (doc?.openclawChannels ?? []).filter(c => c.name !== channel);
      channels.push({ name: channel, token: encryptField(token) });
      await systemSettings().updateOne({ _id: "system" }, { $set: { openclawChannels: channels } });
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.delete("/openclaw/configure-channel/:channel", { preHandler: requireRole("admin") }, async (request, reply) => {
    const channel = (request.params as any).channel;
    try {
      await runInContainer(`openclaw channels remove --channel ${channel}`);
      const doc = await systemSettings().findOne({ _id: "system" });
      const channels = (doc?.openclawChannels ?? []).filter(c => c.name !== channel);
      await systemSettings().updateOne({ _id: "system" }, { $set: { openclawChannels: channels } });
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/openclaw/skills", { preHandler: requireRole("admin") }, async (_request, reply) => {
    try {
      const { stdout } = await runInContainer("openclaw skills list --json 2>/dev/null");
      const data = JSON.parse(stdout);
      let allowlist: string[] | null = null;
      try {
        const { stdout: cfg } = await runInContainer("openclaw config get agents.defaults.skills --json 2>/dev/null || echo 'null'");
        const parsed = JSON.parse(cfg);
        if (Array.isArray(parsed)) allowlist = parsed;
      } catch { /* no allowlist set */ }

      const skills = (data.skills as any[])
        .filter(s => s.source === "openclaw-workspace")
        .map(s => ({
          name: s.name,
          description: s.description,
          eligible: s.eligible,
          enabled: allowlist === null ? true : allowlist.includes(s.name),
        }));
      return { skills, allowlist };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.put("/openclaw/skills", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body as any;
    const enabled: string[] = Array.isArray(body?.enabled) ? body.enabled : [];
    try {
      await runInContainer(
        `openclaw config set agents.defaults.skills --strict-json ${JSON.stringify(JSON.stringify(enabled))}`
      );
      await systemSettings().updateOne(
        { _id: "system" },
        { $set: { openclawSkills: enabled, updatedAt: new Date() } }
      );
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/openclaw/pairing", { preHandler: requireRole("admin") }, async () => {
    try {
      const { stdout } = await runInContainer("openclaw pairing list --channel discord --json 2>/dev/null || echo '{}'");
      try {
        const parsed = JSON.parse(stdout);
        return Array.isArray(parsed.requests) ? parsed.requests : [];
      } catch { return []; }
    } catch {
      return [];
    }
  });

  app.post("/openclaw/pairing/approve", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body as any;
    const code = String(body?.code ?? "").trim();
    const channel = String(body?.channel ?? "discord");
    if (!code) return reply.code(400).send({ error: "code is required" });
    try {
      await runInContainer(`openclaw pairing approve --channel ${channel} --notify ${code}`);
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/openclaw/pairing/approved", { preHandler: requireRole("admin") }, async () => {
    const channels = ["discord", "slack", "telegram", "imessage", "msteams"];
    const result: { channel: string; id: string; name: string }[] = [];
    for (const ch of channels) {
      try {
        const { stdout } = await runInContainer(
          `cat ~/.openclaw/credentials/${ch}-default-allowFrom.json 2>/dev/null || echo '{}'`
        );
        const parsed = JSON.parse(stdout);
        const ids: string[] = Array.isArray(parsed.allowFrom) ? parsed.allowFrom : [];
        for (const id of ids) {
          result.push({ channel: ch, id, name: id });
        }
      } catch { /* channel not configured */ }
    }
    return result;
  });

  app.post("/openclaw/pairing/revoke", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { channel, id } = request.body as any;
    if (!channel || !id) return reply.code(400).send({ error: "channel and id required" });
    try {
      const file = `~/.openclaw/credentials/${channel}-default-allowFrom.json`;
      const { stdout } = await runInContainer(`cat ${file} 2>/dev/null || echo '{}'`);
      const parsed = JSON.parse(stdout);
      const allowFrom: string[] = Array.isArray(parsed.allowFrom) ? parsed.allowFrom : [];
      const updated = JSON.stringify({ ...parsed, allowFrom: allowFrom.filter(u => u !== id) });
      await runInContainer(`echo ${JSON.stringify(updated)} > ${file}`);
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });

  app.get("/openclaw/dashboard-url", { preHandler: requireRole("admin") }, async (request, reply) => {
    try {
      const { stdout } = await runInContainer(
        "openclaw dashboard --no-open 2>&1 | grep 'Dashboard URL:' | sed 's/.*Dashboard URL: //'"
      );
      const host = (request.headers["host"] as string ?? "localhost:8080").split(":")[0];
      return { url: stdout.trim().replace("127.0.0.1", host) };
    } catch {
      return reply.code(503).send({ error: "OpenClaw is not running" });
    }
  });

  app.post("/openclaw/configure-db-credentials", { preHandler: requireRole("admin") }, async (request, reply) => {
    const body = request.body as any;
    const username = String(body?.username ?? "").trim();
    const password = String(body?.password ?? "");
    if (!username || !password) return reply.code(400).send({ error: "Username and password are required" });

    try {
      updateEnvFile(STACK_ENV_PATH, {
        OPENCLAW_API_USERNAME: username,
        OPENCLAW_API_PASSWORD: password,
      });
      await new Promise<void>((resolve, reject) =>
        exec(
          `docker compose -p av -f /run/secrets/docker-compose.yml --env-file /run/secrets/stack.env up -d --no-deps openclaw`,
          (err) => err ? reject(err) : resolve()
        )
      );
      return { success: true };
    } catch (err: any) {
      return reply.code(500).send({ error: err.message });
    }
  });
}
