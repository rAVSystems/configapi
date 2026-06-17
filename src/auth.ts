import type { Role } from "./types.js";

export function normalizeClientIp(raw: string | undefined): string | undefined {
  if (!raw) return undefined;

  const first = raw.split(",")[0]?.trim();
  if (!first) return undefined;

  const noV6Map = first.startsWith("::ffff:") ? first.slice("::ffff:".length) : first;
  const noPort =
    noV6Map.match(/^\d+\.\d+\.\d+\.\d+:/) ? noV6Map.split(":")[0] : noV6Map;

  return noPort;
}

export function getClientIp(request: any): string | undefined {
  const xff = request.headers?.["x-forwarded-for"] as string | undefined;
  return normalizeClientIp(xff ?? request.ip);
}

export async function requireAuth(request: any, reply: any): Promise<void> {
  try {
    await request.jwtVerify();
  } catch {
    reply.code(401).send({ error: "Unauthorized" });
  }
}

export function requireAnyRole(roles: Role[]) {
  return async (request: any, reply: any): Promise<void> => {
    await requireAuth(request, reply);
    if (reply.sent) return;

    const userRoles: Role[] = request.user?.roles ?? [];
    const ok = roles.some((r) => userRoles.includes(r));
    if (!ok) {
      reply.code(403).send({ error: "Forbidden" });
    }
  };
}

export function requireRole(role: Role) {
  return requireAnyRole([role]);
}
