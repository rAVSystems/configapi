import crypto from "crypto";
import type { EncryptedField } from "./types.js";

export const SETTINGS_ENCRYPTION_KEY = Buffer.from(
  process.env.SETTINGS_ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex"),
  "hex"
).slice(0, 32);

export function encryptField(value: string): EncryptedField {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", SETTINGS_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  return { iv: iv.toString("hex"), data: encrypted.toString("hex") };
}

export function decryptField(field: EncryptedField): string {
  const iv = Buffer.from(field.iv, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SETTINGS_ENCRYPTION_KEY, iv);
  const decrypted = Buffer.concat([decipher.update(Buffer.from(field.data, "hex")), decipher.final()]);
  return decrypted.toString("utf8");
}

export function hashPasswordScrypt(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 32);
  return `scrypt:${salt.toString("hex")}:${hash.toString("hex")}`;
}

export function verifyPasswordScrypt(password: string, stored: string): boolean {
  const parts = stored.split(":");
  if (parts.length !== 3) return false;

  const [algo, saltHex, hashHex] = parts;
  if (algo !== "scrypt" || !saltHex || !hashHex) return false;

  const salt = Buffer.from(saltHex, "hex");
  const expected = Buffer.from(hashHex, "hex");
  const actual = crypto.scryptSync(password, salt, expected.length);

  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}
