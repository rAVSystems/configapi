import "@fastify/jwt";

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: { sub: string; username: string; roles: ("admin" | "editor" | "viewer")[] };
    user: { sub: string; username: string; roles: ("admin" | "editor" | "viewer")[] };
  }
}

export type Role = "admin" | "editor" | "viewer";

export type RoomConfig = {
  roomId: string;
  campus?: string;
  building?: string;
  ip?: string;
  updatedAt: Date;
  updatedBy: string;
  version: number;
  [key: string]: unknown;
};

export type RoomConfigDoc = {
  _id: string;
  config: RoomConfig;
};

export type RoomStateDoc = { _id: string; updatedAt: Date; [key: string]: unknown };

export type UsageEventDoc = {
  _id: string;
  roomId: string;
  timestamp: Date;
  event: string;
  payload: Record<string, unknown>;
};

export type ReportDoc = {
  _id: string;
  title: string;
  createdAt: Date;
  createdBy: string;
  body: string;
};

export type TemplateDoc = {
  _id: string;
  name: string;
  icon: string;
  createdby: string;
  created: string;
  permission: string;
  config: Record<string, unknown>;
};

export type EncryptedField = { iv: string; data: string };

export type OpenclawChannel = {
  name: string;
  token: EncryptedField;
};

export type SystemSettings = {
  _id: "system";
  setupComplete: boolean;
  portalName: string;
  apiCredentials: { username: EncryptedField; password: EncryptedField };
  anthropicApiKey: EncryptedField;
  openclawCredentials: { username: EncryptedField; password: EncryptedField };
  openclawLlmProvider: string;
  openclawLlmModel: string;
  openclawLlmApiKey: EncryptedField;
  openclawSkills: string[];
  openclawChannels: OpenclawChannel[];
  mqttCredentials: { username: EncryptedField; password: EncryptedField };
  dbCredentials: { username: EncryptedField; password: EncryptedField };
  updatedAt: Date;
  updatedBy: string;
};

export type AppUser = {
  username: string;
  passwordHash: string;
  roles: Role[];
  isActive: boolean;
  mustChangePassword?: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt?: Date | null;
};

export type AppUserDoc = {
  _id: string;
  user: AppUser;
};

export interface ScheduledJob {
  name: string;
  script: string;
  cron: string;
  enabled?: boolean;
}
