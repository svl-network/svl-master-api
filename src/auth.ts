/*
 * Copyright (c) 2026 Sunveil Network. All rights reserved.
 *
 * PROPRIETARY & CONFIDENTIAL
 *
 * This file is part of Sunveil Connect and the Sunveil Bridge.
 * Unauthorized copying of this file, via any medium, is strictly prohibited.
 *
 * You are permitted to view and compile this source code for personal,
 * private use with your own server infrastructure only. Redistribution,
 * public hosting, or creating derivative works is a direct violation of copyright.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

// Ensure environment variables are loaded immediately on module import
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const APP_ROOT = process.env.APP_ROOT || (fs.existsSync(path.resolve(process.cwd(), "package.json")) ? process.cwd() : path.resolve(__dirname, ".."));

export const getDataDir = (): string => {
  if (process.env.DATA_DIR) {
    const dir = path.resolve(process.env.DATA_DIR);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    return dir;
  }
  const localDataDir = path.resolve(APP_ROOT, "data");
  if (!fs.existsSync(localDataDir)) {
    fs.mkdirSync(localDataDir, { recursive: true });
  }
  return localDataDir;
};

const getDbPath = (): string => {
  return path.resolve(getDataDir(), "database.json");
};

const getLicensesDbPath = (): string => {
  return path.resolve(getDataDir(), "licenses.json");
};

const getAuditLogDbPath = (): string => {
  return path.resolve(getDataDir(), "audit_logs.json");
};

const DB_FILE = getDbPath();
const LICENSES_DB_FILE = getLicensesDbPath();
const AUDIT_LOG_FILE = getAuditLogDbPath();

// Dynamic fallback secrets generated at boot if not supplied via environment variables
const dynamicJwtSecret = crypto.randomBytes(32).toString("hex");
let dynamicAdminSecret: string | null = null;

export const getJwtSecret = (): string => {
  return process.env.JWT_SECRET || process.env.API_SECRET_KEY || dynamicJwtSecret;
};

export type TrustLevel = "TRUSTED" | "NORMAL" | "SUSPICIOUS" | "QUARANTINED" | "BANNED";

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  salt: string;
  licenseKey: string;
  serverKey: string;
  serverKeys?: string[] | undefined;       // Array of owned server keys (up to serverSlots)
  serverSlots?: number | undefined;        // Max servers allowed (1 free, up to 4 upgraded)
  createdAt: number;
  boosts: number;
  lastBoostAt?: number | undefined;
  sponsored: boolean;
  role?: "admin" | "user" | undefined;
  isBanned?: boolean | undefined;
  banReason?: string | undefined;
  bannedAt?: number | undefined;
  bannerUrl?: string | undefined;
  links?: {
    store?: string | undefined;
    discord?: string | undefined;
    website?: string | undefined;
  } | undefined;
  tosAgreedAt?: number | undefined;
  tosAgreedIp?: string | undefined;
  antiMalwareAffirmed?: boolean | undefined;
  
  // Hardware Fingerprint & Trust Score Metrics
  hwid?: string | undefined;
  ipHistory?: string[] | undefined;
  trustScore?: number | undefined;         // 0 to 100
  trustLevel?: TrustLevel | undefined;
  trustFlags?: string[] | undefined;
  lastTrustEvaluation?: number | undefined;
}

export type LicenseTier = "FREE" | "PRO" | "SPONSOR" | "ENTERPRISE" | "PARTNER" | "CUSTOM";

export interface LicenseEntry {
  licenseKey: string;
  tier: LicenseTier;
  ownerEmail?: string | undefined;
  serverKey?: string | undefined;
  status: "active" | "revoked" | "banned" | "expired";
  createdAt: number;
  expiresAt?: number | null | undefined;
  revocationReason?: string | undefined;
  maxPlayers?: number | undefined;
  notes?: string | undefined;
}

export interface AuditLogEntry {
  id: string;
  timestamp: number;
  action: string;
  target: string;
  actor: string;
  ip?: string | undefined;
  details?: string | undefined;
}

export const userStore = new Map<string, User>(); // email -> User
export const userIdStore = new Map<string, User>(); // id -> User
export const licenseStore = new Map<string, LicenseEntry>(); // licenseKey -> LicenseEntry
export const auditLogs: AuditLogEntry[] = [];

// Index maps for instant hardware and IP correlation
export const hwidAccountMap = new Map<string, Set<string>>(); // hwid -> Set<userId>
export const ipAccountMap = new Map<string, Set<string>>();   // ip -> Set<userId>

/**
 * Re-indexes all user HWIDs and IPs in memory
 */
export const rebuildSecurityIndexes = () => {
  hwidAccountMap.clear();
  ipAccountMap.clear();

  for (const user of userStore.values()) {
    if (user.hwid) {
      const cleanHwid = user.hwid.trim().toLowerCase();
      if (!hwidAccountMap.has(cleanHwid)) {
        hwidAccountMap.set(cleanHwid, new Set());
      }
      hwidAccountMap.get(cleanHwid)!.add(user.id);
    }

    const ips = new Set<string>();
    if (user.tosAgreedIp) ips.add(user.tosAgreedIp.trim());
    if (Array.isArray(user.ipHistory)) {
      for (const ip of user.ipHistory) {
        if (ip && typeof ip === "string") ips.add(ip.trim());
      }
    }

    for (const ip of ips) {
      if (!ipAccountMap.has(ip)) {
        ipAccountMap.set(ip, new Set());
      }
      ipAccountMap.get(ip)!.add(user.id);
    }

    // Ensure serverKeys array and serverSlots default
    if (!user.serverSlots || user.serverSlots < 1) {
      user.serverSlots = user.sponsored ? 4 : (user.role === "admin" ? 4 : 1);
    }
    if (!user.serverKeys || !Array.isArray(user.serverKeys) || user.serverKeys.length === 0) {
      user.serverKeys = user.serverKey ? [user.serverKey] : [];
    } else if (user.serverKey && !user.serverKeys.includes(user.serverKey)) {
      user.serverKeys.unshift(user.serverKey);
    }
  }
};

/**
 * Indexes a single user into memory correlation indexes
 */
export const indexUserTrust = (user: User) => {
  if (user.hwid) {
    const cleanHwid = user.hwid.trim().toLowerCase();
    if (!hwidAccountMap.has(cleanHwid)) {
      hwidAccountMap.set(cleanHwid, new Set());
    }
    hwidAccountMap.get(cleanHwid)!.add(user.id);
  }

  const ips = new Set<string>();
  if (user.tosAgreedIp) ips.add(user.tosAgreedIp.trim());
  if (Array.isArray(user.ipHistory)) {
    for (const ip of user.ipHistory) {
      if (ip && typeof ip === "string") ips.add(ip.trim());
    }
  }

  for (const ip of ips) {
    if (!ipAccountMap.has(ip)) {
      ipAccountMap.set(ip, new Set());
    }
    ipAccountMap.get(ip)!.add(user.id);
  }
};

/**
 * Calculates Trust Score (0-100) & evaluates Multi-Account Abuse
 */
export interface TrustEvaluationResult {
  score: number;
  level: TrustLevel;
  flags: string[];
  linkedHwidAccounts: number;
  linkedIpAccounts: number;
  blocked: boolean;
  blockReason?: string | undefined;
}

export const evaluateTrustScore = (
  ip: string,
  hwid?: string,
  existingUserId?: string,
  options?: { isNewRegistration?: boolean; email?: string }
): TrustEvaluationResult => {
  let score = 80; // Baseline starting score
  const flags: string[] = [];

  const cleanIp = (ip || "").trim();
  const cleanHwid = (hwid || "").trim().toLowerCase();

  // 1. Hardware ID Evaluation
  let linkedHwidAccounts = 0;
  if (cleanHwid && cleanHwid.length >= 16) {
    const existingUsersWithHwid = hwidAccountMap.get(cleanHwid);
    if (existingUsersWithHwid) {
      for (const uId of existingUsersWithHwid) {
        if (!existingUserId || uId !== existingUserId) {
          linkedHwidAccounts++;
        }
      }
    }

    if (linkedHwidAccounts === 0) {
      score += 15; // Verified unique hardware device
      flags.push("UNIQUE_HARDWARE");
    } else if (linkedHwidAccounts === 1) {
      score -= 30; // 2nd account on same physical hardware
      flags.push("MULTI_ACCOUNT_HWID_SECONDARY");
    } else if (linkedHwidAccounts >= 2) {
      score -= 60; // 3+ accounts on same physical hardware
      flags.push("MULTI_ACCOUNT_HWID_FARM");
    }
  } else if (!cleanHwid && options?.isNewRegistration) {
    score -= 10;
    flags.push("MISSING_DEVICE_FINGERPRINT");
  }

  // 2. IP Subnet & Address Evaluation
  let linkedIpAccounts = 0;
  if (cleanIp && cleanIp !== "127.0.0.1" && cleanIp !== "localhost") {
    const existingUsersWithIp = ipAccountMap.get(cleanIp);
    if (existingUsersWithIp) {
      for (const uId of existingUsersWithIp) {
        if (!existingUserId || uId !== existingUserId) {
          linkedIpAccounts++;
        }
      }
    }

    if (linkedIpAccounts === 0) {
      score += 5;
      flags.push("CLEAN_IP");
    } else if (linkedIpAccounts === 1) {
      score -= 15;
      flags.push("SHARED_IP_NETWORK");
    } else if (linkedIpAccounts >= 2) {
      score -= 40;
      flags.push("IP_ACCOUNT_VELOCITY_HIGH");
    }
  }

  // 3. Email Pattern Evaluation
  if (options?.email) {
    const emailLower = options.email.toLowerCase();
    const tempDomains = ["tempmail", "10minutemail", "guerrillamail", "throwaway", "disposable", "mailinator", "trashmail"];
    for (const td of tempDomains) {
      if (emailLower.includes(td)) {
        score -= 50;
        flags.push("DISPOSABLE_EMAIL_DOMAIN");
        break;
      }
    }
  }

  // Clamp score between 0 and 100
  score = Math.max(0, Math.min(100, score));

  // Determine Trust Level
  let level: TrustLevel = "NORMAL";
  if (score >= 85) level = "TRUSTED";
  else if (score >= 50) level = "NORMAL";
  else if (score >= 25) level = "SUSPICIOUS";
  else level = "QUARANTINED";

  // Check Registration Block Decision
  let blocked = false;
  let blockReason: string | undefined;

  if (options?.isNewRegistration) {
    // If the hardware already has an existing account and attempts to make another free account
    if (linkedHwidAccounts >= 1) {
      blocked = true;
      blockReason = "Device limit reached: An account is already registered on this hardware. Free tier is limited to 1 server per device. You can add up to 3-4 servers by upgrading your server slots in the dashboard.";
    } else if (linkedIpAccounts >= 3) {
      blocked = true;
      blockReason = "Network registration limit exceeded. Multiple accounts have been registered from your IP address. Please upgrade server slots in your existing dashboard.";
    } else if (score < 25) {
      blocked = true;
      blockReason = "Registration blocked by Trust Sentinel: High multi-account anomaly detected.";
    }
  }

  return {
    score,
    level,
    flags,
    linkedHwidAccounts,
    linkedIpAccounts,
    blocked,
    blockReason
  };
};

/**
 * Persists the user database to disk (JSON)
 */
export const saveDatabaseToDisk = () => {
  try {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = {
      users: Array.from(userStore.values()),
      savedAt: Date.now()
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf8");
    rebuildSecurityIndexes();
  } catch (err) {
    console.error("Failed to save database to disk:", err);
  }
};

/**
 * Persists licenses to disk
 */
export const saveLicensesToDisk = () => {
  try {
    const dir = path.dirname(LICENSES_DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = {
      licenses: Array.from(licenseStore.values()),
      savedAt: Date.now()
    };
    fs.writeFileSync(LICENSES_DB_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Failed to save licenses to disk:", err);
  }
};

/**
 * Persists audit logs to disk
 */
export const saveAuditLogsToDisk = () => {
  try {
    const dir = path.dirname(AUDIT_LOG_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const trimmedLogs = auditLogs.slice(-2000);
    fs.writeFileSync(AUDIT_LOG_FILE, JSON.stringify({ logs: trimmedLogs, savedAt: Date.now() }, null, 2), "utf8");
  } catch (err) {
    console.error("Failed to save audit logs to disk:", err);
  }
};

/**
 * Appends an entry to the cryptographic audit log
 */
export const logAdminAction = (action: string, target: string, actor: string, ip?: string, details?: string) => {
  const entry: AuditLogEntry = {
    id: "log_" + crypto.randomBytes(6).toString("hex"),
    timestamp: Date.now(),
    action,
    target,
    actor,
    ip: ip || "internal",
    details: details || ""
  };
  auditLogs.unshift(entry);
  if (auditLogs.length > 2000) {
    auditLogs.pop();
  }
  saveAuditLogsToDisk();
  console.log(`🔒 [AUDIT] [${entry.action}] Target: ${entry.target} | Actor: ${entry.actor} | IP: ${entry.ip} ${details ? "| " + details : ""}`);
};

/**
 * Loads the user database from disk
 */
export const loadDatabaseFromDisk = () => {
  try {
    if (fs.existsSync(DB_FILE)) {
      const raw = fs.readFileSync(DB_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.users)) {
        for (const u of parsed.users) {
          // Normalize serverSlots & serverKeys
          if (!u.serverSlots || u.serverSlots < 1) {
            u.serverSlots = u.sponsored ? 4 : 1;
          }
          if (!u.serverKeys || !Array.isArray(u.serverKeys) || u.serverKeys.length === 0) {
            u.serverKeys = u.serverKey ? [u.serverKey] : [];
          }
          if (u.trustScore === undefined) {
            u.trustScore = 85;
            u.trustLevel = "TRUSTED";
            u.trustFlags = ["ESTABLISHED_ACCOUNT"];
          }

          userStore.set(u.email.toLowerCase(), u);
          userIdStore.set(u.id, u);

          if (u.licenseKey && !licenseStore.has(u.licenseKey)) {
            licenseStore.set(u.licenseKey, {
              licenseKey: u.licenseKey,
              tier: u.sponsored ? "SPONSOR" : "FREE",
              ownerEmail: u.email,
              serverKey: u.serverKey,
              status: u.isBanned ? "banned" : "active",
              createdAt: u.createdAt || Date.now(),
              notes: "Migrated from user database"
            });
          }
        }
      }
    }
  } catch (err) {
    console.error("Failed to load database from disk:", err);
  }

  // Load licenses
  try {
    if (fs.existsSync(LICENSES_DB_FILE)) {
      const raw = fs.readFileSync(LICENSES_DB_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.licenses)) {
        for (const lic of parsed.licenses) {
          licenseStore.set(lic.licenseKey, lic);
        }
      }
    }
  } catch (err) {
    console.error("Failed to load licenses from disk:", err);
  }

  // Load audit logs
  try {
    if (fs.existsSync(AUDIT_LOG_FILE)) {
      const raw = fs.readFileSync(AUDIT_LOG_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.logs)) {
        auditLogs.length = 0;
        auditLogs.push(...parsed.logs);
      }
    }
  } catch (err) {
    console.error("Failed to load audit logs from disk:", err);
  }

  seedDemoUser();
  rebuildSecurityIndexes();
  saveDatabaseToDisk();
  saveLicensesToDisk();
};

/**
 * Generates a cryptographically strong license key in SVL format (SVL-<TIER>-XXXX-XXXX)
 */
export const generateLicenseKey = (tier: LicenseTier = "FREE"): string => {
  const p1 = crypto.randomBytes(2).toString("hex").toUpperCase();
  const p2 = crypto.randomBytes(2).toString("hex").toUpperCase();
  const cleanTier = tier.toUpperCase().replace(/[^A-Z]/g, "").slice(0, 10) || "FREE";
  return `SVL-${cleanTier}-${p1}-${p2}`;
};

/**
 * Hashes a password using scrypt with a unique random salt
 */
export const hashPassword = (password: string): { hash: string; salt: string } => {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { hash, salt };
};

/**
 * Verifies a password against the stored hash and salt using timing-safe comparison
 */
export const verifyPassword = (password: string, storedHash: string, salt: string): boolean => {
  try {
    const hash = crypto.scryptSync(password, salt, 64).toString("hex");
    const a = Buffer.from(hash, "hex");
    const b = Buffer.from(storedHash, "hex");
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
};

export const getBootstrapAdminSecret = (): string => {
  if (process.env.ADMIN_SECRET_KEY && process.env.ADMIN_SECRET_KEY.trim().length > 0) {
    return process.env.ADMIN_SECRET_KEY.trim();
  }
  if (!dynamicAdminSecret) {
    dynamicAdminSecret = crypto.randomBytes(24).toString("hex");
    console.warn(`\n⚠️  [SECURITY WARNING] No ADMIN_SECRET_KEY environment variable set in .env / platform!`);
    console.warn(`🔑 [SECURITY] Generated ephemeral admin bootstrap secret: ${dynamicAdminSecret}\n`);
  }
  return dynamicAdminSecret;
};

/**
 * Timing-safe admin token verifier against environment master secrets
 */
export const verifyAdminSecret = (providedSecret: string): boolean => {
  if (!providedSecret || typeof providedSecret !== "string") return false;
  
  const validSecrets = [
    process.env.ADMIN_SECRET_KEY,
    process.env.MASTER_API_TOKEN,
    process.env.API_SECRET_KEY,
    dynamicAdminSecret
  ].filter((s): s is string => typeof s === "string" && s.trim().length > 0);

  if (validSecrets.length === 0) {
    validSecrets.push(getBootstrapAdminSecret());
  }

  for (const valid of validSecrets) {
    const a = Buffer.from(crypto.createHash("sha256").update(providedSecret.trim()).digest("hex"));
    const b = Buffer.from(crypto.createHash("sha256").update(valid.trim()).digest("hex"));
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) {
      return true;
    }
  }
  return false;
};

/**
 * Base64URL encoder
 */
const base64UrlEncode = (str: string): string => {
  return Buffer.from(str)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
};

/**
 * Base64URL decoder
 */
const base64UrlDecode = (str: string): string => {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64").toString("utf8");
};

/**
 * Generates a lightweight, secure JWT without external dependencies
 */
export const generateJWT = (user: User): string => {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: user.id,
    email: user.email,
    licenseKey: user.licenseKey,
    role: user.role || "user",
    serverSlots: user.serverSlots || 1,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 30 * 24 * 3600 // 30 days expiration
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac("sha256", getJwtSecret())
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
};

/**
 * Generates an Admin-specific elevated JWT
 */
export const generateAdminJWT = (actor = "admin_root"): string => {
  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    sub: "admin_" + crypto.randomBytes(4).toString("hex"),
    email: "admin@sunveil.net",
    role: "admin",
    actor,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 12 * 3600 // 12 hours max session for admin
  };

  const encodedHeader = base64UrlEncode(JSON.stringify(header));
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const signature = crypto
    .createHmac("sha256", getJwtSecret())
    .update(data)
    .digest("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  return `${data}.${signature}`;
};

/**
 * Verifies and decodes a JWT token
 */
export const verifyJWT = (token: string): { sub: string; email: string; licenseKey: string; role?: string; actor?: string; serverSlots?: number } | null => {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;

    const headerB64 = parts[0];
    const payloadB64 = parts[1];
    const sigB64 = parts[2];
    if (!headerB64 || !payloadB64 || !sigB64) return null;

    const data = `${headerB64}.${payloadB64}`;

    const expectedSig = crypto
      .createHmac("sha256", getJwtSecret())
      .update(data)
      .digest("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

    const a = Buffer.from(sigB64);
    const b = Buffer.from(expectedSig);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return null;
    }

    const payloadJson = base64UrlDecode(payloadB64);
    const payload = JSON.parse(payloadJson);

    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired token
    }

    return payload;
  } catch {
    return null;
  }
};

/**
 * Initializes seed demo developer account with predictable persistent credentials
 */
export const seedDemoUser = () => {
  if (process.env.SEED_DEMO_USER !== "true" && !process.env.DEMO_USER_PASSWORD) {
    return;
  }
  const email = (process.env.DEMO_USER_EMAIL || "developer@sunveil.net").toLowerCase();
  const password = process.env.DEMO_USER_PASSWORD || crypto.randomBytes(16).toString("hex");
  const defaultLicense = process.env.DEMO_USER_LICENSE || generateLicenseKey("SPONSOR");

  if (!userStore.has(email)) {
    const { hash, salt } = hashPassword(password);
    const user: User = {
      id: "usr_developer_sunveil",
      email,
      passwordHash: hash,
      salt,
      licenseKey: defaultLicense,
      serverKey: "svl_demo_realm",
      serverKeys: ["svl_demo_realm"],
      serverSlots: 4,
      createdAt: Date.now() - 30 * 24 * 3600 * 1000,
      boosts: 15,
      sponsored: true,
      role: "admin",
      trustScore: 98,
      trustLevel: "TRUSTED",
      trustFlags: ["SYSTEM_ADMIN_ACCOUNT", "VERIFIED_DEVICE"],
      bannerUrl: "https://raw.githubusercontent.com/PolyMC/PolyMC/develop/launcher/resources/multimc/scalable/multimc.svg",
      links: {
        store: "https://sunveilsmp.tebex.io",
        discord: "https://discord.gg/sunveil",
        website: "https://sunveil.net"
      }
    };
    userStore.set(email, user);
    userIdStore.set(user.id, user);

    if (!licenseStore.has(defaultLicense)) {
      licenseStore.set(defaultLicense, {
        licenseKey: defaultLicense,
        tier: "SPONSOR",
        ownerEmail: email,
        serverKey: user.serverKey,
        status: "active",
        createdAt: user.createdAt,
        notes: "Official Sunveil Developer Demo License"
      });
    }
  }
};

/**
 * Searches for a user by email, serverKey, licenseKey, or ID (case-insensitive)
 */
export const findUserByIdentifier = (identifier: string): User | undefined => {
  if (!identifier) return undefined;
  const clean = identifier.trim().toLowerCase();
  
  if (userStore.has(clean)) {
    return userStore.get(clean);
  }
  
  for (const user of userStore.values()) {
    if (
      user.email.toLowerCase() === clean ||
      user.serverKey.toLowerCase() === clean ||
      (user.serverKeys && user.serverKeys.some(k => k.toLowerCase() === clean)) ||
      user.licenseKey.toLowerCase() === clean ||
      user.id.toLowerCase() === clean
    ) {
      return user;
    }
  }
  return undefined;
};
