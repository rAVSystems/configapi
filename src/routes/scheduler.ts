import fs from "fs";
import path from "path";
import yaml from "js-yaml";
import { execSync } from "child_process";
import type { FastifyInstance } from "fastify";
import { requireRole, requireAnyRole } from "../auth.js";
import type { ScheduledJob } from "../types.js";

const SCHEDULER_SCRIPTS_DIR = "/scheduler/scripts";
const SCHEDULER_JOBS_FILE = "/scheduler/jobs.yaml";

function readJobsFile(): { jobs: ScheduledJob[] } {
  try {
    const content = fs.readFileSync(SCHEDULER_JOBS_FILE, "utf8");
    const parsed = (yaml.load(content) as any) || { jobs: [] };
    parsed.jobs = (parsed.jobs || []).map((j: ScheduledJob) => ({ enabled: true, ...j }));
    return parsed;
  } catch {
    return { jobs: [] };
  }
}

function writeJobsFile(config: { jobs: ScheduledJob[] }): void {
  fs.writeFileSync(SCHEDULER_JOBS_FILE, yaml.dump(config), "utf8");
}

async function reloadScheduler(): Promise<void> {
  execSync(`docker kill --signal=SIGHUP av-scheduler`);
}

export async function schedulerRoutes(app: FastifyInstance) {
  app.get("/scheduler/jobs", { preHandler: requireAnyRole(["admin", "editor", "viewer"]) }, async () => {
    return readJobsFile();
  });

  app.post("/scheduler/jobs", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name, script, cron, code } = request.body as {
      name: string; script: string; cron: string; code: string;
    };

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
    } else {
      config.jobs.push({ name, script, cron, enabled: true });
    }
    writeJobsFile(config);

    try { await reloadScheduler(); } catch { /* scheduler may not be running */ }

    return { success: true, name, script, cron };
  });

  app.patch("/scheduler/jobs/:name", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name } = request.params as { name: string };
    const { enabled } = request.body as { enabled: boolean };

    if (typeof enabled !== "boolean") {
      return reply.code(400).send({ error: "enabled must be a boolean" });
    }

    const config = readJobsFile();
    const job = config.jobs.find(j => j.name === name);
    if (!job) return reply.code(404).send({ error: "Job not found" });

    job.enabled = enabled;
    writeJobsFile(config);

    try { await reloadScheduler(); } catch { /* scheduler may not be running */ }

    return { success: true };
  });

  app.delete("/scheduler/jobs/:name", { preHandler: requireRole("admin") }, async (request, reply) => {
    const { name } = request.params as { name: string };

    const config = readJobsFile();
    const job = config.jobs.find(j => j.name === name);
    if (!job) return reply.code(404).send({ error: "Job not found" });

    config.jobs = config.jobs.filter(j => j.name !== name);
    writeJobsFile(config);

    const scriptPath = path.join(SCHEDULER_SCRIPTS_DIR, job.script);
    if (fs.existsSync(scriptPath)) fs.unlinkSync(scriptPath);

    try { await reloadScheduler(); } catch { /* scheduler may not be running */ }

    return { success: true };
  });
}
