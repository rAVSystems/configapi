import { Db, MongoClient } from "mongodb";
import type {
  RoomConfigDoc,
  RoomStateDoc,
  UsageEventDoc,
  ReportDoc,
  TemplateDoc,
  SystemSettings,
  AppUserDoc,
} from "./types.js";

export const MONGO_URI =
  process.env.MONGO_URI ||
  "mongodb://avapp:avrocks@192.168.1.225:27017/avdb?authSource=avdb";

export const client = new MongoClient(MONGO_URI);
export let db: Db;

export function initDb(database: Db) {
  db = database;
}

export const roomConfigs = () => db.collection<RoomConfigDoc>("rooms");
export const roomStates = () => db.collection<RoomStateDoc>("state");
export const usageEvents = () => db.collection<UsageEventDoc>("usage");
export const reports = () => db.collection<ReportDoc>("reports");
export const templates = () => db.collection<TemplateDoc>("templates");
export const systemSettings = () => db.collection<SystemSettings>("settings");
export const users = () => db.collection<AppUserDoc>("users");

export const ROOM_SUMMARY_PROJECTION = {
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
} as const;
