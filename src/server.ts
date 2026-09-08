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

import Fastify, { type FastifyRequest, type FastifyReply } from "fastify";
import cors from "@fastify/cors";
import helmet from "@fastify/helmet";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import fastifyMultipart from "@fastify/multipart";
import cookie from "@fastify/cookie";
import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { pipeline } from "node:stream/promises";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const APP_ROOT = process.env.APP_ROOT || (fs.existsSync(path.resolve(process.cwd(), "package.json")) ? process.cwd() : path.resolve(__dirname, ".."));

import {
  type User,
  type LicenseTier,
  type LicenseEntry,
  type AuditLogEntry,
  type TrustLevel,
  userStore,
  userIdStore,
  licenseStore,
  auditLogs,
  hwidAccountMap,
  ipAccountMap,
  evaluateTrustScore,
  indexUserTrust,
  rebuildSecurityIndexes,
  hashPassword,
  verifyPassword,
  generateJWT,
  verifyJWT,
  generateAdminJWT,
  verifyAdminSecret,
  logAdminAction,
  generateLicenseKey,
  seedDemoUser,
  loadDatabaseFromDisk,
  saveDatabaseToDisk,
  saveLicensesToDisk,
  getDataDir,
  findUserByIdentifier,
  isTokenLike,
  generateRandomServerKey,
  checkAdminIpLockout,
  recordAdminFailedAttempt,
  recordAdminSuccess,
  unblockAdminIp,
  adminIpLockoutMap
} from "./auth.js";
import { relayServer } from "./tunnel/RelayServer.js";

const API_SECRET_KEY = process.env.API_SECRET_KEY || process.env.MASTER_API_TOKEN || crypto.randomBytes(32).toString("hex");
const CLIENT_SECRET = process.env.SVL_CLIENT_SECRET || crypto.randomBytes(32).toString("hex");
const COOKIE_SECRET = process.env.COOKIE_SECRET || crypto.randomBytes(32).toString("hex");
const MAX_FILE_SIZE = (Number(process.env.MAX_FILE_SIZE_MB) || 150) * 1024 * 1024;
const DATA_MODS_DIR = path.resolve(getDataDir(), "mods");
const PUBLIC_DIR = fs.existsSync(path.resolve(process.cwd(), "public"))
  ? path.resolve(process.cwd(), "public")
  : path.resolve(APP_ROOT, "public");

if (!fs.existsSync(DATA_MODS_DIR)) {
  fs.mkdirSync(DATA_MODS_DIR, { recursive: true });
}

if (!fs.existsSync(PUBLIC_DIR)) {
  fs.mkdirSync(PUBLIC_DIR, { recursive: true });
}

const fastify = Fastify({
  logger: {
    transport: {
      target: "pino-pretty",
      options: {
        colorize: true
      }
    }
  }
});

// Register Plugins BEFORE routes
await fastify.register(cookie, {
  secret: COOKIE_SECRET
});

await fastify.register(cors, {
  origin: (origin, cb) => {
    // Allow non-browser requests (e.g. Minecraft plugins, launchers, curl)
    if (!origin) return cb(null, true);

    const allowed = [
      "https://realms.sunveil.net",
      "https://dash.sunveil.net",
      "https://sunveil.net",
      "https://www.sunveil.net",
      "http://localhost:3000",
      "http://localhost:3001",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3001"
    ];

    if (allowed.includes(origin) || origin.endsWith(".sunveil.net")) {
      return cb(null, true);
    }

    // In production, reject unknown cross-origin web requests
    return cb(new Error("CORS origin not allowed"), false);
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
});

await fastify.register(helmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        "'unsafe-inline'",
        "'unsafe-eval'",
        "https://pagead2.googlesyndication.com",
        "https://*.googlesyndication.com",
        "https://*.google.com",
        "https://*.doubleclick.net",
        "https://*.google-analytics.com",
        "https://*.googletagmanager.com",
        "https://adservice.google.com"
      ],
      scriptSrcAttr: ["'unsafe-inline'"],
      scriptSrcElem: [
        "'self'",
        "'unsafe-inline'",
        "https://pagead2.googlesyndication.com",
        "https://*.googlesyndication.com",
        "https://*.google.com",
        "https://*.doubleclick.net",
        "https://*.google-analytics.com",
        "https://*.googletagmanager.com",
        "https://adservice.google.com"
      ],
      styleSrc: [
        "'self'",
        "'unsafe-inline'",
        "https://fonts.googleapis.com",
        "https://*.google.com",
        "https://*.googlesyndication.com"
      ],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: [
        "'self'",
        "data:",
        "https:",
        "http:",
        "https://mc-heads.net",
        "https://raw.githubusercontent.com",
        "https://*.googlesyndication.com",
        "https://*.google.com",
        "https://*.doubleclick.net"
      ],
      frameSrc: [
        "'self'",
        "https://googleads.g.doubleclick.net",
        "https://*.googlesyndication.com",
        "https://*.google.com",
        "https://*.doubleclick.net",
        "https://sunveilsmp.tebex.io"
      ],
      connectSrc: [
        "'self'",
        "https://realms.sunveil.net",
        "https://dash.sunveil.net",
        "https://api.sunveil.net",
        "https://sunveil.net",
        "https://www.sunveil.net",
        "https://*.googlesyndication.com",
        "https://*.google.com",
        "https://*.doubleclick.net",
        "https://*.google-analytics.com",
        "http://localhost:3001",
        "http://127.0.0.1:3001"
      ]
    }
  },
  crossOriginEmbedderPolicy: false
});

// Register Rate Limiting
await fastify.register(rateLimit, {
  max: 300,
  timeWindow: "1 minute",
  allowList: (req) => {
    const auth = req.headers.authorization;
    if (auth && auth.startsWith("Bearer ") && isValidToken(auth.substring(7).trim())) {
      return true;
    }
    if (req.url.startsWith("/static/mods/")) {
      return true;
    }
    return false;
  },
  errorResponseBuilder: function (_request, context) {
    return {
      statusCode: 429,
      error: "Too Many Requests",
      message: `Rate limit exceeded. Try again in ${context.after}.`
    };
  }
});

await fastify.register(fastifyMultipart, { limits: { fileSize: MAX_FILE_SIZE } });

// Register Static File Providers
await fastify.register(fastifyStatic, {
  root: DATA_MODS_DIR,
  prefix: "/static/mods/",
  index: false,
  list: false,
  decorateReply: false
});

await fastify.register(fastifyStatic, {
  root: PUBLIC_DIR,
  prefix: "/",
  decorateReply: true,
  index: ["index.html"]
});

// Allow application/octet-stream raw streaming
fastify.addContentTypeParser("application/octet-stream", (_req, payload, done) => {
  done(null, payload);
});

// Global preHandler for native launcher / API signature enforcement
fastify.addHook("preHandler", async (request, reply) => {
  if (!request.url.startsWith("/api/v1/")) return;
  if (request.url.startsWith("/api/v1/health")) return;
  if (request.url.startsWith("/api/v1/auth/")) return;
  if (request.url.startsWith("/api/v1/admin/")) return;
  if (request.url.startsWith("/api/v1/updates/latest")) return;
  if (request.url.startsWith("/api/v1/servers")) return;
  if (request.url.startsWith("/api/v1/storage/check")) return;
  if (request.url.startsWith("/api/v1/user/")) return;

  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return;
  }

  if (request.cookies && (request.cookies.svl_session || request.cookies.svl_admin_session)) {
    return;
  }

  const clientSecret = request.headers["x-svl-client-secret"];
  const hwid = request.headers["x-svl-hwid"];

  if (!clientSecret || clientSecret !== CLIENT_SECRET) {
    fastify.log.warn(`Unauthorized access attempt from IP: ${request.ip}`);
    return reply.status(403).send({
      statusCode: 403,
      error: "Forbidden",
      message: "Invalid or missing client signature."
    });
  }

  if (!hwid || typeof hwid !== "string" || hwid.length < 32) {
    fastify.log.warn(`Missing or invalid HWID from IP: ${request.ip}`);
    return reply.status(400).send({
      statusCode: 400,
      error: "Bad Request",
      message: "Hardware fingerprint verification failed."
    });
  }
});

export interface ModInfo {
  projectId: string;
  fileName: string;
  sha256: string;
  downloadUrl: string;
  tier?: "official" | "community";
  targetFolder?: string;
}

export interface ServerLinks {
  store?: string | undefined;
  discord?: string | undefined;
  website?: string | undefined;
}

export interface ServerPerformance {
  cpuPercent?: number | undefined;
  ramUsedMB?: number | undefined;
  ramMaxMB?: number | undefined;
  tps?: number | undefined;
  uptimeSeconds?: number | undefined;
}

export interface PlayerEntry {
  name: string;
  uuid?: string | undefined;
  ping?: number | undefined;
  joinedAt?: number | undefined;
}

export interface ServerPayload {
  serverKey: string;
  name: string;
  ip: string;
  port: number;
  region?: string | undefined;
  version: {
    minecraft: string;
    loader: string;
    loaderVersion: string;
  };
  status: {
    players: number;
    maxPlayers: number;
    motd: string;
  };
  icon?: string | undefined;
  mods: ModInfo[];
  lastHeartbeat?: number | undefined;
  verified?: boolean | undefined;
  boosts?: number | undefined;
  sponsored?: boolean | undefined;
  bannerUrl?: string | null | undefined;
  links?: ServerLinks | undefined;
  isBanned?: boolean | undefined;
  banReason?: string | undefined;
  bannedAt?: number | undefined;
  performance?: ServerPerformance | undefined;
  playerList?: (string | PlayerEntry)[] | undefined;
  ownerEmail?: string | undefined;
  slotIndex?: number | undefined;
  isCustom?: boolean | undefined;
}

// Persistent Server Stores
const SERVERS_DB_FILE = path.resolve(getDataDir(), "servers.json");
const serverStore = new Map<string, ServerPayload>();
const serverOwnerStore = new Map<string, string>(); // serverKey -> tokenHash

export const saveServersToDisk = () => {
  try {
    const dir = path.dirname(SERVERS_DB_FILE);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const data = {
      servers: Array.from(serverStore.entries()),
      serverOwners: Array.from(serverOwnerStore.entries()),
      savedAt: Date.now()
    };
    fs.writeFileSync(SERVERS_DB_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error("Failed to save servers database to disk:", err);
  }
};

export const loadServersFromDisk = () => {
  try {
    if (fs.existsSync(SERVERS_DB_FILE)) {
      const raw = fs.readFileSync(SERVERS_DB_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed.servers)) {
        for (const [k, s] of parsed.servers) {
          serverStore.set(k, s);
        }
      }
      if (Array.isArray(parsed.serverOwners)) {
        for (const [k, o] of parsed.serverOwners) {
          serverOwnerStore.set(k, o);
        }
      }
    }
  } catch (err) {
    console.error("Failed to load servers database from disk:", err);
  }
};

// Sanitizer for untrusted string inputs
const sanitizeString = (val: unknown, maxLen = 128): string => {
  if (typeof val !== "string") return "";
  return val
    .replace(/<[^>]*>/g, "") // Strip HTML tags
    .replace(/[\x00-\x1F\x7F-\x9F]/g, "") // Strip control characters
    .trim()
    .slice(0, maxLen);
};

const hashToken = (token: string): string => {
  return crypto.createHash("sha256").update(token).digest("hex");
};

export function isValidToken(token: string): boolean {
  if (!token) return false;
  if (token === API_SECRET_KEY) return true;
  if (process.env.MASTER_API_TOKEN && token === process.env.MASTER_API_TOKEN) return true;

  // Check user accounts and their multi-server keys
  for (const user of userStore.values()) {
    if (user.licenseKey && user.licenseKey === token) return true;
    if (user.serverKey && user.serverKey === token) return true;
    if (user.serverKeys && user.serverKeys.includes(token)) return true;
  }

  // Check licenseStore
  if (licenseStore.has(token)) {
    const lic = licenseStore.get(token)!;
    if (lic.status === "active") return true;
  }

  return false;
}

export const RESERVED_SUBDOMAINS = new Set([
  "api", "admin", "administrator", "realms", "realm", "dash", "dashboard",
  "auth", "login", "register", "ws", "relay", "direct", "mail", "email",
  "cdn", "sunveil", "svl", "www", "proxy", "tunnel", "status", "bot",
  "ping", "root", "support", "test", "help", "app", "system", "connect",
  "minecraft", "mc", "server", "nodes", "edge", "master", "modrinth"
]);

export function validateSubdomainOrKey(name: string): { valid: boolean; error?: string } {
  if (!name || typeof name !== "string") {
    return { valid: false, error: "Subdomain or Server Key is required." };
  }
  const clean = name.trim().toLowerCase();
  if (clean.length < 3 || clean.length > 32) {
    return { valid: false, error: "Must be between 3 and 32 characters long." };
  }
  if (!/^[a-z0-9][a-z0-9_-]*[a-z0-9]$/i.test(clean) && !/^[a-z0-9]{3,32}$/i.test(clean)) {
    return { valid: false, error: "Only letters, numbers, hyphens, and underscores are allowed." };
  }
  if (RESERVED_SUBDOMAINS.has(clean)) {
    return { valid: false, error: `'${clean}' is a reserved system keyword and cannot be used.` };
  }

  const sensitiveTokens = [
    (process.env.API_SECRET_KEY || "").toLowerCase(),
    (process.env.MASTER_API_TOKEN || "").toLowerCase(),
    (process.env.JWT_SECRET || "").toLowerCase()
  ].filter(t => t.length > 0);

  for (const secret of sensitiveTokens) {
    if (clean === secret || (secret.length >= 6 && clean.includes(secret))) {
      return { valid: false, error: "Security violation: Server key cannot match or contain system master tokens." };
    }
  }

  if (clean.includes("secret") || clean.includes("apikey") || clean.includes("token_master") || isTokenLike(clean)) {
    return { valid: false, error: "Security violation: Server key cannot be an API token, license key, or system secret." };
  }

  return { valid: true };
}

export function isServerKeyClaimed(serverKey: string, currentUserId?: string): boolean {
  const cleanKey = serverKey.trim().toLowerCase();

  // Check userStore
  for (const u of userStore.values()) {
    if (currentUserId && u.id === currentUserId) continue;
    if (u.serverKey && u.serverKey.toLowerCase() === cleanKey) return true;
    if (u.serverKeys && u.serverKeys.some(k => k.toLowerCase() === cleanKey)) return true;
    if (u.licenseKey && u.licenseKey.toLowerCase() === cleanKey) return true;
  }

  // Check serverStore
  for (const [key] of serverStore.entries()) {
    if (key.toLowerCase() === cleanKey) {
      if (currentUserId) {
        const ownerHash = serverOwnerStore.get(key);
        const currentUser = userIdStore.get(currentUserId);
        if (currentUser && ownerHash && (
          ownerHash === hashToken(currentUser.licenseKey) ||
          ownerHash === hashToken(currentUser.serverKey) ||
          (currentUser.serverKeys && currentUser.serverKeys.some(sk => ownerHash === hashToken(sk)))
        )) {
          continue;
        }
      }
      return true;
    }
  }

  return false;
}

// Bearer Token Authentication Pre-Handler
const requireAuth = async (request: FastifyRequest, reply: FastifyReply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Missing or invalid Bearer authentication token."
    });
  }

  const token = authHeader.substring(7).trim();
  if (!isValidToken(token)) {
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Invalid API secret token."
    });
  }
};

const getClientIp = (req: FastifyRequest): string => {
  const cfIp = req.headers["cf-connecting-ip"];
  if (typeof cfIp === "string" && cfIp.trim().length > 0) return cfIp.trim();
  const xRealIp = req.headers["x-real-ip"];
  if (typeof xRealIp === "string" && xRealIp.trim().length > 0) return xRealIp.trim();
  const xForwardedFor = req.headers["x-forwarded-for"];
  if (typeof xForwardedFor === "string" && xForwardedFor.trim().length > 0) {
    return xForwardedFor.split(",")[0]!.trim();
  }
  return req.ip || "unknown";
};

// Hardened Secret Admin Authentication Pre-Handler with Brute-Force & IP Lockout Sentinel
const requireAdminAuth = async (request: FastifyRequest, reply: FastifyReply) => {
  const clientIp = getClientIp(request);

  // 1. Check if IP is currently locked out
  const lockout = checkAdminIpLockout(clientIp);
  if (lockout.locked) {
    return reply.status(429).send({
      statusCode: 429,
      error: "Too Many Requests",
      message: `Administrative access locked out for your IP (${clientIp}) due to repeated unauthorized attempts. Try again in ${Math.ceil(lockout.remainingSeconds / 60)} minutes.`,
      remainingSeconds: lockout.remainingSeconds
    });
  }

  const adminSecretHeader = request.headers["x-svl-admin-secret"];
  if (typeof adminSecretHeader === "string" && verifyAdminSecret(adminSecretHeader)) {
    (request as any).adminActor = "header_master_secret";
    recordAdminSuccess(clientIp);
    return;
  }

  // 2. Check HttpOnly Cookie
  let token: string | undefined;
  if (request.cookies && request.cookies.svl_admin_session) {
    token = request.cookies.svl_admin_session;
  }

  // 3. Fallback to Authorization Bearer header
  if (!token) {
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.substring(7).trim();
    }
  }

  if (token) {
    if (verifyAdminSecret(token)) {
      (request as any).adminActor = "bearer_master_secret";
      recordAdminSuccess(clientIp);
      return;
    }

    const decoded = verifyJWT(token);
    if (decoded && (decoded.role === "admin" || (decoded as any).actor)) {
      (request as any).adminActor = decoded.email || (decoded as any).actor || "admin";
      recordAdminSuccess(clientIp);
      return;
    }
  }

  const failState = recordAdminFailedAttempt(clientIp, "unauthorized_probe");
  logAdminAction("UNAUTHORIZED_ACCESS_ATTEMPT", request.url, "unknown", clientIp, `Blocked invalid admin credentials (Attempt ${failState.failures})`);

  if (failState.locked) {
    return reply.status(429).send({
      statusCode: 429,
      error: "Too Many Requests",
      message: `Too many unauthorized attempts. Your IP (${clientIp}) has been temporarily locked out for ${Math.ceil(failState.remainingSeconds / 60)} minutes.`,
      remainingSeconds: failState.remainingSeconds
    });
  }

  return reply.status(403).send({
    statusCode: 403,
    error: "Forbidden",
    message: "Administrative credentials required. Access logged."
  });
};

const getBaseUrl = (req: { headers: Record<string, string | string[] | undefined>; protocol: string }) => {
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${process.env.PORT || 3001}`;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "http";
  return `${proto}://${host}`;
};

// 1. Health-Check Endpunkte
fastify.get("/health", async () => {
  return { status: "ok", uptime: process.uptime(), registeredServers: serverStore.size };
});

fastify.get("/api/v1/health", async () => {
  return { status: "ok", uptime: process.uptime(), registeredServers: serverStore.size };
});

// 2. Storage Check Endpunkt
fastify.get<{ Params: { sha256: string } }>("/api/v1/storage/check/:sha256", async (request, reply) => {
  const { sha256 } = request.params;
  if (!sha256 || !/^[a-fA-F0-9]{64}$/.test(sha256)) {
    return reply.status(400).send({ error: "Invalid SHA-256 hash format." });
  }

  const targetFile = path.resolve(DATA_MODS_DIR, `${sha256.toLowerCase()}.jar`);

  if (!targetFile.startsWith(DATA_MODS_DIR)) {
    return reply.status(400).send({ error: "Invalid file path traversal detected." });
  }

  const exists = fs.existsSync(targetFile);
  const baseUrl = getBaseUrl(request);
  const url = `${baseUrl}/static/mods/${sha256.toLowerCase()}.jar`;

  return { exists, url: exists ? url : null };
});

// 3. Storage Upload Endpunkt
fastify.post("/api/v1/storage/upload", {
  preHandler: [requireAuth],
  config: {
    rateLimit: {
      max: 10,
      timeWindow: "1 minute"
    }
  }
}, async (request, reply) => {
  let tempFilePath: string | null = null;
  try {
    const isMultipart = request.isMultipart();
    const hash = crypto.createHash("sha256");

    const tempFileName = `temp_${Date.now()}_${crypto.randomBytes(8).toString("hex")}.tmp`;
    tempFilePath = path.resolve(DATA_MODS_DIR, tempFileName);

    if (!tempFilePath.startsWith(DATA_MODS_DIR)) {
      return reply.status(400).send({ error: "Path traversal violation." });
    }

    const writeStream = fs.createWriteStream(tempFilePath);
    let totalBytes = 0;

    if (isMultipart) {
      const data = await request.file();
      if (!data) {
        return reply.status(400).send({ error: "No file provided in multipart body." });
      }

      data.file.on("data", (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_FILE_SIZE) {
          data.file.destroy(new Error("File size limit exceeded."));
        }
        hash.update(chunk);
      });
      await pipeline(data.file, writeStream);
    } else {
      request.raw.on("data", (chunk: Buffer) => {
        totalBytes += chunk.length;
        if (totalBytes > MAX_FILE_SIZE) {
          request.raw.destroy(new Error("File size limit exceeded."));
        }
        hash.update(chunk);
      });
      await pipeline(request.raw, writeStream);
    }

    const fd = fs.openSync(tempFilePath, "r");
    const magicBuffer = Buffer.alloc(4);
    fs.readSync(fd, magicBuffer, 0, 4, 0);
    fs.closeSync(fd);

    const isZipOrJar = magicBuffer[0] === 0x50 &&
      magicBuffer[1] === 0x4B &&
      magicBuffer[2] === 0x03 &&
      magicBuffer[3] === 0x04;

    if (!isZipOrJar) {
      fs.unlinkSync(tempFilePath);
      return reply.status(400).send({
        error: "Invalid file format",
        message: "Uploaded file does not have valid JAR/ZIP magic bytes (PK..)."
      });
    }

    const fileBuffer = fs.readFileSync(tempFilePath);
    const forbiddenExts = [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".elf", ".scr", ".dll", ".so", ".msi", ".pif", ".hta", ".wsf", ".cpl", ".reg"];
    const fileContentStr = fileBuffer.toString("latin1").toLowerCase();
    for (const ext of forbiddenExts) {
      if (fileContentStr.includes(ext)) {
        fs.unlinkSync(tempFilePath);
        return reply.status(400).send({
          error: "Malware/Executable Prohibited",
          message: `Security Policy Violation: JAR archive contains unauthorized executable or script payload (${ext}).`
        });
      }
    }

    const calculatedSha256 = hash.digest("hex").toLowerCase();
    const finalFilePath = path.resolve(DATA_MODS_DIR, `${calculatedSha256}.jar`);

    if (!finalFilePath.startsWith(DATA_MODS_DIR)) {
      fs.unlinkSync(tempFilePath);
      return reply.status(400).send({ error: "Path traversal violation." });
    }

    if (fs.existsSync(finalFilePath)) {
      fs.unlinkSync(tempFilePath);
    } else {
      fs.renameSync(tempFilePath, finalFilePath);
    }

    const baseUrl = getBaseUrl(request);
    const downloadUrl = `${baseUrl}/static/mods/${calculatedSha256}.jar`;

    return reply.status(201).send({
      status: "ok",
      sha256: calculatedSha256,
      url: downloadUrl
    });
  } catch (err) {
    if (tempFilePath && fs.existsSync(tempFilePath)) {
      fs.unlinkSync(tempFilePath);
    }
    request.log.error(err);
    return reply.status(500).send({ error: "File upload processing failed." });
  }
});

// 4. Heartbeat Endpunkt
fastify.post<{ Body: ServerPayload }>("/api/v1/heartbeat", {
  preHandler: [requireAuth]
}, async (request, reply) => {
  const payload = request.body;

  if (!payload || !payload.serverKey || !payload.ip || !payload.version) {
    return reply.status(400).send({
      error: "Bad Request",
      message: "Required fields missing (serverKey, ip, version)."
    });
  }

  let rawServerKey = sanitizeString(payload.serverKey, 64);
  const authHeader = request.headers.authorization;
  const token = (request as any).authToken || (authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7).trim() : "");
  if (!token || !isValidToken(token)) {
    return reply.status(401).send({
      error: "Unauthorized",
      message: "Valid authentication token required."
    });
  }
  const currentTokenHash = hashToken(token);

  // Link server to user account
  let matchedUser: User | undefined;
  for (const u of userStore.values()) {
    if (u.licenseKey === token || (u.serverKey && u.serverKey === token) || (u.serverKeys && u.serverKeys.includes(rawServerKey))) {
      matchedUser = u;
      break;
    }
  }
  if (!matchedUser && licenseStore.has(token)) {
    const lic = licenseStore.get(token)!;
    if (lic.ownerEmail) {
      matchedUser = userStore.get(lic.ownerEmail.toLowerCase());
    }
  }
  if (!matchedUser) {
    matchedUser = findUserByIdentifier(token);
  }

  // Safety & Auto-Correction: If master token or token-like string was passed as serverKey, protect & auto-correct it
  if (isTokenLike(rawServerKey) || rawServerKey.toLowerCase() === token.toLowerCase()) {
    if (matchedUser && matchedUser.serverKey && !isTokenLike(matchedUser.serverKey)) {
      rawServerKey = matchedUser.serverKey;
    } else {
      rawServerKey = generateRandomServerKey(isServerKeyClaimed);
      if (matchedUser) {
        matchedUser.serverKey = rawServerKey;
        if (!matchedUser.serverKeys) matchedUser.serverKeys = [];
        if (!matchedUser.serverKeys.includes(rawServerKey)) matchedUser.serverKeys.push(rawServerKey);
        saveDatabaseToDisk();
      }
    }
  } else if (matchedUser) {
    if (matchedUser.serverKey !== rawServerKey && (!matchedUser.serverKeys || !matchedUser.serverKeys.includes(rawServerKey))) {
      if (!matchedUser.serverKeys) matchedUser.serverKeys = [matchedUser.serverKey];
      if (matchedUser.serverKeys.length < (matchedUser.serverSlots || 1)) {
        matchedUser.serverKeys.push(rawServerKey);
      }
      saveDatabaseToDisk();
    }
  }

  // Clean up previous stale offline ghost entries for this user / license
  if (matchedUser) {
    for (const [oldKey, oldSrv] of serverStore.entries()) {
      if (oldKey !== rawServerKey) {
        const isOldKeyOwned = (matchedUser.serverKeys && matchedUser.serverKeys.includes(oldKey)) ||
          oldKey === matchedUser.serverKey ||
          serverOwnerStore.get(oldKey) === currentTokenHash;
        if (isOldKeyOwned) {
          const tunnel = relayServer.getTunnel(oldKey);
          if (!tunnel && (!oldSrv.lastHeartbeat || Date.now() - oldSrv.lastHeartbeat > 60000)) {
            serverStore.delete(oldKey);
            serverOwnerStore.delete(oldKey);
          }
        }
      }
    }
  }

  // Check License Store Status
  if (licenseStore.has(token)) {
    const lic = licenseStore.get(token)!;
    if (lic.status === "banned" || lic.status === "revoked") {
      return reply.status(403).send({
        error: "Forbidden",
        message: `License is ${lic.status}. Reason: ${lic.revocationReason || "Administrative enforcement"}`
      });
    }
    if (lic.serverKey !== rawServerKey) {
      lic.serverKey = rawServerKey;
      saveLicensesToDisk();
    }
  }

  // Check Server Ban Status
  const existingServer = serverStore.get(rawServerKey);
  if (existingServer?.isBanned || matchedUser?.isBanned) {
    return reply.status(403).send({
      error: "Forbidden",
      message: `This server is banned by Sunveil Administration. Reason: ${existingServer?.banReason || matchedUser?.banReason || "Policy violation"}`
    });
  }

  // Anti-Spoofing: Verify serverKey ownership
  const registeredOwnerHash = serverOwnerStore.get(rawServerKey);
  if (registeredOwnerHash && registeredOwnerHash !== currentTokenHash && (!matchedUser || hashToken(matchedUser.licenseKey) !== registeredOwnerHash)) {
    return reply.status(403).send({
      error: "Forbidden",
      message: "Server key ownership mismatch."
    });
  }
  serverOwnerStore.set(rawServerKey, currentTokenHash);

  const rawMods = Array.isArray(payload.mods) ? payload.mods : [];

  const mods: ModInfo[] = rawMods.map((m) => {
    const safeProjectId = sanitizeString(m.projectId, 64);
    const safeFileName = sanitizeString(m.fileName, 128);
    const safeSha256 = typeof m.sha256 === "string" ? m.sha256.toLowerCase().trim() : "";
    const isOfficial = m.downloadUrl && m.downloadUrl.startsWith("https://cdn.modrinth.com/");

    return {
      projectId: safeProjectId,
      fileName: safeFileName,
      sha256: safeSha256,
      downloadUrl: typeof m.downloadUrl === "string" ? m.downloadUrl.trim() : "",
      tier: m.tier || (isOfficial ? "official" : "community"),
      targetFolder: sanitizeString((m as any).targetFolder, 32) || "mods"
    };
  });

  const isVerified = mods.length > 0 && mods.every((m) =>
    m.tier === "official" && m.downloadUrl && m.downloadUrl.startsWith("https://cdn.modrinth.com/")
  );

  let incomingIp = (request.headers["cf-connecting-ip"] as string)?.trim()
    || (request.headers["x-real-ip"] as string)?.trim()
    || (request.headers["x-forwarded-for"] as string)?.split(",")[0]?.trim()
    || request.ip
    || request.socket.remoteAddress
    || "";

  if (incomingIp.startsWith("::ffff:")) {
    incomingIp = incomingIp.substring(7);
  }

  const requestedIp = typeof payload.ip === "string" ? payload.ip.trim() : "";
  let resolvedIp = incomingIp || "127.0.0.1";
  if (requestedIp && requestedIp.toLowerCase() !== "auto" && requestedIp !== "127.0.0.1" && requestedIp !== "localhost") {
    resolvedIp = sanitizeString(requestedIp, 64);
  } else if (incomingIp) {
    resolvedIp = incomingIp;
  }

  const detectedCountry = (request.headers["cf-ipcountry"] as string)?.trim() || "EU";

  let performanceData: ServerPerformance | undefined;
  if (payload.performance && typeof payload.performance === "object") {
    performanceData = {
      cpuPercent: Math.min(100, Math.max(0, Number(payload.performance.cpuPercent) || 0)),
      ramUsedMB: Math.max(0, Number(payload.performance.ramUsedMB) || 0),
      ramMaxMB: Math.max(0, Number(payload.performance.ramMaxMB) || 0),
      tps: Math.min(20, Math.max(0, Number(payload.performance.tps) || 20)),
      uptimeSeconds: Math.max(0, Number(payload.performance.uptimeSeconds) || 0)
    };
  }

  const rawPlayerList = Array.isArray(payload.playerList) ? payload.playerList : [];
  const safePlayerList = rawPlayerList.map(p => {
    if (typeof p === "string") return sanitizeString(p, 32);
    if (p && typeof p === "object" && typeof p.name === "string") {
      return {
        name: sanitizeString(p.name, 32),
        uuid: typeof p.uuid === "string" ? sanitizeString(p.uuid, 64) : undefined,
        ping: typeof p.ping === "number" ? Math.max(0, p.ping) : undefined
      };
    }
    return "";
  }).filter(Boolean);

  const serverData: ServerPayload = {
    serverKey: rawServerKey,
    name: sanitizeString(payload.name, 64),
    ip: resolvedIp,
    port: Number(payload.port) || 25565,
    region: detectedCountry,
    version: {
      minecraft: sanitizeString(payload.version?.minecraft, 32),
      loader: sanitizeString(payload.version?.loader, 32),
      loaderVersion: sanitizeString(payload.version?.loaderVersion, 64)
    },
    status: {
      players: Math.max(0, Number(payload.status?.players) || (safePlayerList.length > 0 ? safePlayerList.length : 0)),
      maxPlayers: Math.max(0, Number(payload.status?.maxPlayers) || 0),
      motd: sanitizeString(payload.status?.motd, 128)
    },
    icon: typeof payload.icon === "string" && payload.icon.length > 0 ? payload.icon.slice(0, 100000) : (typeof (payload as any).logo === "string" ? (payload as any).logo.slice(0, 100000) : undefined),
    mods,
    lastHeartbeat: Date.now(),
    verified: isVerified,
    boosts: Math.max(0, Number(payload.boosts) || 0),
    sponsored: Boolean(payload.sponsored),
    bannerUrl: typeof payload.bannerUrl === "string" && payload.bannerUrl.length > 0 ? payload.bannerUrl.trim().slice(0, 500) : null,
    links: payload.links ? {
      store: sanitizeString(payload.links.store, 256),
      discord: sanitizeString(payload.links.discord, 256),
      website: sanitizeString(payload.links.website, 256)
    } : { store: "", discord: "", website: "" },
    isBanned: false,
    performance: performanceData,
    playerList: safePlayerList,
    ownerEmail: matchedUser?.email || undefined
  };

  serverStore.set(rawServerKey, serverData);
  saveServersToDisk();

  return {
    status: "ok",
    verified: isVerified,
    registeredMods: mods.length,
    officialMods: mods.filter(m => m.tier === "official").length,
    communityMods: mods.filter(m => m.tier === "community").length
  };
});

// 5. Öffentliche Serverliste
fastify.get("/api/v1/servers", {
  config: {
    rateLimit: {
      max: 60,
      timeWindow: "10 seconds"
    }
  }
}, async () => {
  const now = Date.now();
  const activeServers: any[] = [];

  for (const [, srv] of serverStore.entries()) {
    if (srv.isBanned) continue;

    const tunnel = relayServer.getTunnel(srv.serverKey);
    const isOnline = Boolean(tunnel || (srv.lastHeartbeat && (now - srv.lastHeartbeat < 90000)));
    if (!isOnline) {
      continue; // Strictly omit offline servers from the public directory
    }
    
    // Privacy & Security: NEVER leak backend origin IP address in public endpoints.
    // Always resolve to the Sunveil SNI relay hostname or active tunnel host.
    const relayHost = `${srv.serverKey.toLowerCase().replace(/[^a-z0-9_-]/g, "")}.realms.sunveil.net`;
    const resolvedIp = tunnel ? tunnel.publicHost : (srv.isCustom ? srv.ip : relayHost);
    const resolvedPort = tunnel ? tunnel.assignedPort : (srv.isCustom ? srv.port : 25565);
    const onlinePlayers = (srv.status?.players !== undefined ? srv.status.players : (srv.playerList ? srv.playerList.length : 0));

    const safePublicServer = {
      serverKey: srv.serverKey,
      name: srv.name,
      icon: srv.icon,
      ip: resolvedIp,
      port: resolvedPort,
      region: srv.region || "EU",
      version: srv.version,
      verified: Boolean(srv.verified),
      boosts: srv.boosts || 0,
      sponsored: Boolean(srv.sponsored),
      bannerUrl: srv.bannerUrl || null,
      links: srv.links || { store: "", discord: "", website: "" },
      online: isOnline,
      isCustom: Boolean(srv.isCustom),
      modCount: srv.mods ? srv.mods.length : 0,
      tunnel: tunnel ? {
        active: true,
        publicHost: tunnel.publicHost,
        publicPort: tunnel.assignedPort,
        activeClients: tunnel.activeClients,
        connectedAt: tunnel.connectedAt
      } : { active: false },
      status: {
        online: isOnline,
        players: onlinePlayers,
        maxPlayers: srv.status?.maxPlayers || 0,
        motd: srv.status?.motd || ""
      }
    };
    activeServers.push(safePublicServer);
  }

  return activeServers.sort((a, b) => {
    const aScore = (a.boosts || 0) + (a.sponsored ? 10000 : 0);
    const bScore = (b.boosts || 0) + (b.sponsored ? 10000 : 0);
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    return (b.status?.players || 0) - (a.status?.players || 0);
  });
});

// 6. Manifest-Abruf
fastify.get<{ Params: { serverKey: string } }>("/api/v1/servers/:serverKey/manifest", async (request, reply) => {
  const safeServerKey = sanitizeString(request.params.serverKey, 64);
  const srv = serverStore.get(safeServerKey);
  if (!srv) {
    return reply.status(404).send({ error: "Server not found or offline." });
  }

  if (srv.isBanned) {
    return reply.status(403).send({ error: "Server suspended", message: srv.banReason || "This server has been banned by administration." });
  }

  const tunnel = relayServer.getTunnel(srv.serverKey);
  const relayHost = `${srv.serverKey.toLowerCase().replace(/[^a-z0-9_-]/g, "")}.realms.sunveil.net`;
  const resolvedIp = tunnel ? tunnel.publicHost : (srv.isCustom ? srv.ip : relayHost);
  const resolvedPort = tunnel ? tunnel.assignedPort : (srv.isCustom ? srv.port : 25565);

  return {
    serverKey: srv.serverKey,
    name: srv.name,
    icon: srv.icon,
    ip: resolvedIp,
    port: resolvedPort,
    version: srv.version,
    verified: srv.verified,
    mods: srv.mods,
    boosts: srv.boosts || 0,
    sponsored: Boolean(srv.sponsored),
    bannerUrl: srv.bannerUrl || null,
    links: srv.links || { store: "", discord: "", website: "" }
  };
});

// 8. Latest Updates & Auto-Updater Matrix
fastify.get("/api/v1/updates/latest", async () => {
  return {
    client: {
      version: "1.0.4",
      mandatory: false,
      url: "https://realms.sunveil.net/releases.html",
      downloadUrl: "https://realms.sunveil.net/downloads/SVL-Connect-v1.0.4-Windows-x64-Portable.zip",
      platforms: {
        windows: {
          version: "1.0.4",
          downloadUrl: "https://realms.sunveil.net/downloads/SVL-Connect-v1.0.4-Windows-x64-Portable.zip",
          portableUrl: "https://realms.sunveil.net/downloads/SVL-Connect-v1.0.4-Windows-x64-Portable.zip"
        }
      },
      changelog: "SVL Connect v1.0.4: Hardened anti-ban IP isolation, friendly random key resolution, automatic background update detection."
    },
    bridge: {
      version: "2.3.0",
      url: "https://realms.sunveil.net/releases.html",
      downloadUrl: "https://realms.sunveil.net/downloads/svl-bridge-paper.jar",
      downloads: {
        paper: "https://realms.sunveil.net/downloads/svl-bridge-paper.jar",
        fabric: "https://realms.sunveil.net/downloads/svl-bridge-fabric.jar",
        forge: "https://realms.sunveil.net/downloads/svl-bridge-forge.jar",
        "forge-1.20.1": "https://realms.sunveil.net/downloads/svl-bridge-forge-1.20.1.jar",
        neoforge: "https://realms.sunveil.net/downloads/svl-bridge-neoforge.jar",
        "neoforge-1.20.4": "https://realms.sunveil.net/downloads/svl-bridge-neoforge-1.20.4.jar"
      }
    }
  };
});

// Download Redirection / Direct Serve Routes
fastify.get("/download", async (_request, reply) => {
  return reply.redirect("/downloads/svl-connect-windows-x64.zip", 302);
});

fastify.get("/api/v1/download/launcher", async (_request, reply) => {
  return reply.redirect("/downloads/svl-connect-windows-x64.zip", 302);
});

// User JWT Authentication Pre-Handler
const requireUserAuth = async (request: FastifyRequest, reply: FastifyReply) => {
  // 1. Check HttpOnly Cookie
  let token: string | undefined;
  if (request.cookies && request.cookies.svl_session) {
    token = request.cookies.svl_session;
  }

  // 2. Fallback to Authorization Bearer header (for plugins, CLI, curl)
  if (!token) {
    const authHeader = request.headers.authorization;
    if (authHeader && authHeader.startsWith("Bearer ")) {
      token = authHeader.substring(7).trim();
    }
  }

  if (!token) {
    return reply.status(401).send({
      statusCode: 401,
      error: "Unauthorized",
      message: "Missing or invalid session authorization."
    });
  }

  const payload = verifyJWT(token);
  if (!payload) {
    return reply.status(401).send({
      statusCode: 401,
      error: "Unauthorized",
      message: "Session expired or invalid token."
    });
  }

  const user =
    (payload.sub ? userIdStore.get(payload.sub) : undefined) ||
    (payload.email ? userStore.get(payload.email.trim().toLowerCase()) : undefined);
  if (!user) {
    return reply.status(404).send({
      statusCode: 404,
      error: "Not Found",
      message: "User account not found."
    });
  }

  if (user.isBanned) {
    return reply.status(403).send({
      statusCode: 403,
      error: "Account Suspended",
      message: `Your account has been banned: ${user.banReason || "Violation of Terms of Service."}`
    });
  }

  (request as any).user = user;
};

// 9. Auth Register with Hardware Fingerprinting & Trust Score Sentinel
fastify.post<{ Body: { email?: string; password?: string; tosAgreed?: boolean; tosPhrase?: string; hwid?: string } }>(
  "/api/v1/auth/register",
  {
    config: {
      rateLimit: {
        max: 8,
        timeWindow: "1 minute"
      }
    }
  },
  async (request, reply) => {
    const { email, password, tosAgreed, tosPhrase, hwid: bodyHwid } = request.body || {};
    if (!email || typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Please provide a valid email address." });
    }

    if (!password || typeof password !== "string" || password.length < 8) {
      return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Password must be at least 8 characters long." });
    }

    if (!tosAgreed) {
      return reply.status(400).send({
        statusCode: 400,
        error: "TOS Agreement Required",
        message: "You must agree to the Sunveil Network Terms of Service and Anti-Malware Policy."
      });
    }

    const cleanPhrase = (tosPhrase || "").toLowerCase().replace(/[^a-z]/g, " ").trim();
    if (!cleanPhrase.includes("agree") || !cleanPhrase.includes("malware") || !cleanPhrase.includes("harm")) {
      return reply.status(400).send({
        statusCode: 400,
        error: "Anti-Bot Verification Failed",
        message: "Please type the required Anti-Malware & Terms of Service confirmation phrase exactly."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();
    if (userStore.has(normalizedEmail)) {
      return reply.status(409).send({ statusCode: 409, error: "Conflict", message: "An account with this email already exists." });
    }

    // Extract Hardware Fingerprint
    const clientHwid = (request.headers["x-svl-hwid"] as string)?.trim() ||
      (request.headers["x-client-device-fingerprint"] as string)?.trim() ||
      bodyHwid?.trim() || "";

    const incomingIp = (request.headers["cf-connecting-ip"] as string)?.trim() ||
      (request.headers["x-real-ip"] as string)?.trim() ||
      request.ip || "";

    // Run Trust Sentinel Anti-Multi-Account Evaluation
    const trustEval = evaluateTrustScore(incomingIp, clientHwid, undefined, {
      isNewRegistration: true,
      email: normalizedEmail
    });

    if (trustEval.blocked) {
      logAdminAction("REGISTRATION_BLOCKED_BY_TRUST_SENTINEL", normalizedEmail, "TrustSentinel", incomingIp, trustEval.blockReason);
      return reply.status(429).send({
        statusCode: 429,
        error: "Multi-Account Limit Reached",
        message: trustEval.blockReason || "Registration restricted to protect network integrity. Free accounts are limited to 1 server slot per device.",
        trustScore: trustEval.score,
        trustLevel: trustEval.level
      });
    }

    const { hash, salt } = hashPassword(password);
    const licenseKey = generateLicenseKey("FREE");
    const serverKey = generateRandomServerKey(isServerKeyClaimed);

    const newUser: User = {
      id: "usr_" + crypto.randomBytes(8).toString("hex"),
      email: normalizedEmail,
      passwordHash: hash,
      salt,
      licenseKey,
      serverKey,
      serverKeys: [serverKey],
      serverSlots: 1, // Standard free tier: 1 server slot (expandable to 4)
      createdAt: Date.now(),
      boosts: 0,
      sponsored: false,
      role: "user",
      links: { store: "", discord: "", website: "" },
      tosAgreedAt: Date.now(),
      tosAgreedIp: incomingIp,
      antiMalwareAffirmed: true,
      hwid: clientHwid || undefined,
      ipHistory: incomingIp ? [incomingIp] : [],
      trustScore: trustEval.score,
      trustLevel: trustEval.level,
      trustFlags: trustEval.flags,
      lastTrustEvaluation: Date.now()
    };

    userStore.set(normalizedEmail, newUser);
    userIdStore.set(newUser.id, newUser);
    indexUserTrust(newUser);
    
    licenseStore.set(licenseKey, {
      licenseKey,
      tier: "FREE",
      ownerEmail: normalizedEmail,
      serverKey,
      status: "active",
      createdAt: Date.now(),
      notes: "Account registration initial free license"
    });

    saveDatabaseToDisk();
    saveLicensesToDisk();

    logAdminAction("USER_REGISTERED", newUser.email, "Registration", incomingIp, `TrustScore: ${newUser.trustScore} (${newUser.trustLevel}) | Slots: 1`);

    const token = generateJWT(newUser);

    const isHttps = request.protocol === "https" || request.headers["x-forwarded-proto"] === "https";
    reply.setCookie("svl_session", token, {
      path: "/",
      httpOnly: true,
      secure: isHttps || process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60
    });

    return {
      success: true,
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        licenseKey: newUser.licenseKey,
        serverSlots: newUser.serverSlots,
        trustScore: newUser.trustScore,
        trustLevel: newUser.trustLevel,
        createdAt: newUser.createdAt,
        antiMalwareAffirmed: true
      }
    };
  }
);

// 10. Auth Login
fastify.post<{ Body: { email?: string; password?: string; hwid?: string } }>("/api/v1/auth/login", async (request, reply) => {
  const { email, password, hwid: bodyHwid } = request.body || {};
  if (!email || !password || typeof email !== "string" || typeof password !== "string") {
    return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Email and password are required." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = userStore.get(normalizedEmail);
  if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
    return reply.status(401).send({ statusCode: 401, error: "Unauthorized", message: "Invalid email or password." });
  }

  if (user.isBanned) {
    return reply.status(403).send({
      statusCode: 403,
      error: "Account Suspended",
      message: `Account is banned: ${user.banReason || "Violation of Terms of Service."}`
    });
  }

  const incomingIp = (request.headers["cf-connecting-ip"] as string)?.trim() || request.ip || "";
  const clientHwid = (request.headers["x-svl-hwid"] as string)?.trim() || bodyHwid?.trim() || user.hwid;

  if (clientHwid && !user.hwid) {
    user.hwid = clientHwid;
  }
  if (incomingIp) {
    if (!user.ipHistory) user.ipHistory = [];
    if (!user.ipHistory.includes(incomingIp)) {
      user.ipHistory.push(incomingIp);
      if (user.ipHistory.length > 20) user.ipHistory.shift();
    }
  }

  indexUserTrust(user);

  // Update Trust Evaluation on Login
  const trustEval = evaluateTrustScore(incomingIp, user.hwid, user.id);
  user.trustScore = trustEval.score;
  user.trustLevel = trustEval.level;
  user.trustFlags = trustEval.flags;
  user.lastTrustEvaluation = Date.now();

  saveDatabaseToDisk();

  const token = generateJWT(user);

  const isHttps = request.protocol === "https" || request.headers["x-forwarded-proto"] === "https";
  reply.setCookie("svl_session", token, {
    path: "/",
    httpOnly: true,
    secure: isHttps || process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60
  });

  return {
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      licenseKey: user.licenseKey,
      serverSlots: user.serverSlots || 1,
      trustScore: user.trustScore,
      trustLevel: user.trustLevel,
      createdAt: user.createdAt,
      role: user.role || "user"
    }
  };
});

// 10b. Auth Logout
fastify.post("/api/v1/auth/logout", async (request, reply) => {
  reply.clearCookie("svl_session", { path: "/" });
  return { success: true, message: "Logged out successfully." };
});

// 11. User Dashboard Metrics & Multi-Server Telemetry
fastify.get("/api/v1/user/dashboard", { preHandler: [requireUserAuth] }, async (request) => {
  const user: User = (request as any).user;
  const now = Date.now();

  const serverKeys = user.serverKeys && user.serverKeys.length > 0 ? user.serverKeys : [user.serverKey];
  const allUserServers: any[] = [];

  for (const sKey of serverKeys) {
    let srv = serverStore.get(sKey);
    const isOnline = !!srv && (now - (srv.lastHeartbeat || 0) < 120000);

    const livePerformance = srv?.performance || {
      cpuPercent: isOnline ? Math.floor(Math.random() * 12) + 8 : 0,
      ramUsedMB: isOnline ? (srv?.mods?.length ? 2048 + srv.mods.length * 48 : 1536) : 0,
      ramMaxMB: 8192,
      tps: isOnline ? 20.0 : 0.0,
      uptimeSeconds: isOnline && srv?.lastHeartbeat ? Math.floor((now - srv.lastHeartbeat) / 1000) + 120 : 0
    };

    const livePlayerList = srv?.playerList || [];

    allUserServers.push({
      serverKey: sKey,
      name: srv?.name || `Server Slot (${sKey})`,
      online: isOnline,
      ip: srv?.ip || "127.0.0.1",
      port: srv?.port || 25565,
      players: srv?.status?.players || 0,
      maxPlayers: srv?.status?.maxPlayers || 50,
      motd: srv?.status?.motd || "",
      version: srv?.version ? `${srv.version.minecraft || "1.21.1"} ${srv.version.loader || ""}`.trim() : "1.21.1",
      modCount: srv?.mods?.length || 0,
      lastHeartbeat: srv?.lastHeartbeat || null,
      boosts: srv?.boosts || user.boosts || 0,
      sponsored: srv?.sponsored || user.sponsored || false,
      bannerUrl: srv?.bannerUrl || null,
      links: srv?.links || { store: "", discord: "", website: "" },
      isBanned: Boolean(srv?.isBanned),
      banReason: srv?.banReason || null,
      performance: livePerformance,
      playerList: livePlayerList
    });
  }

  // Active / Selected Server is primary user.serverKey
  const activeServer = allUserServers.find(s => s.serverKey === user.serverKey) || allUserServers[0] || null;

  return {
    user: {
      id: user.id,
      email: user.email,
      licenseKey: user.licenseKey,
      serverSlots: user.serverSlots || 1,
      usedSlots: serverKeys.length,
      maxSlots: 4,
      canAddServer: serverKeys.length < (user.serverSlots || 1) && serverKeys.length < 4,
      trustScore: user.trustScore || 85,
      trustLevel: user.trustLevel || "TRUSTED",
      trustFlags: user.trustFlags || ["VERIFIED_DEVICE"],
      createdAt: user.createdAt,
      boosts: user.boosts || 0,
      boostCount: user.boosts || 0,
      lastBoostAt: user.lastBoostAt || null,
      nextBoostAt: user.lastBoostAt ? user.lastBoostAt + 24 * 60 * 60 * 1000 : null,
      canBoost: !user.lastBoostAt || (Date.now() - user.lastBoostAt >= 24 * 60 * 60 * 1000),
      sponsored: user.sponsored || false,
      role: user.role || "user",
      bannerUrl: user.bannerUrl || (activeServer?.bannerUrl || null),
      storeUrl: user.links?.store || (activeServer?.links?.store || ""),
      discordInvite: user.links?.discord || (activeServer?.links?.discord || ""),
      links: user.links || (activeServer?.links || { store: "", discord: "", website: "" })
    },
    server: activeServer,
    servers: allUserServers
  };
});

// 12. Create Additional Server Slot (Up to user.serverSlots, max 4)
fastify.post<{ Body: { name?: string; serverKey?: string } }>("/api/v1/user/servers/create", {
  preHandler: [requireUserAuth]
}, async (request, reply) => {
  const user: User = (request as any).user;
  const { name, serverKey: requestedKey } = request.body || {};

  const currentSlots = user.serverSlots || 1;
  const currentKeys = user.serverKeys && user.serverKeys.length > 0 ? user.serverKeys : [user.serverKey];

  if (currentKeys.length >= currentSlots || currentKeys.length >= 4) {
    return reply.status(403).send({
      statusCode: 403,
      error: "Slot Limit Reached",
      message: `You have reached your server slot limit (${currentKeys.length}/${currentSlots}). Upgrade your account slots to add up to 4 servers.`
    });
  }

  let finalKey = "";
  if (requestedKey && requestedKey.trim()) {
    const cleanKey = requestedKey.trim().toLowerCase();
    const validation = validateSubdomainOrKey(cleanKey);
    if (!validation.valid) {
      return reply.status(400).send({ statusCode: 400, error: "Invalid Key", message: validation.error });
    }
    if (isServerKeyClaimed(cleanKey, user.id)) {
      return reply.status(409).send({ statusCode: 409, error: "Conflict", message: `Key '${cleanKey}' is already taken.` });
    }
    finalKey = cleanKey;
  } else {
    finalKey = generateRandomServerKey(isServerKeyClaimed);
  }

  const newServerName = sanitizeString(name || `Server ${currentKeys.length + 1}`, 64);
  const newLicenseKey = generateLicenseKey(user.sponsored ? "SPONSOR" : "FREE");

  // Create license
  licenseStore.set(newLicenseKey, {
    licenseKey: newLicenseKey,
    tier: user.sponsored ? "SPONSOR" : "FREE",
    ownerEmail: user.email,
    serverKey: finalKey,
    status: "active",
    createdAt: Date.now(),
    notes: `Multi-server slot ${currentKeys.length + 1} for ${user.email}`
  });

  // Create initial server entry
  serverStore.set(finalKey, {
    serverKey: finalKey,
    name: newServerName,
    ip: "127.0.0.1",
    port: 25565,
    version: {
      minecraft: "1.21.1",
      loader: "paper",
      loaderVersion: "1.21.1-latest"
    },
    status: {
      players: 0,
      maxPlayers: 50,
      motd: "New Sunveil Realm Server Instance"
    },
    mods: [],
    lastHeartbeat: 0,
    verified: false,
    boosts: 0,
    sponsored: user.sponsored,
    bannerUrl: null,
    links: { store: "", discord: "", website: "" },
    ownerEmail: user.email,
    slotIndex: currentKeys.length + 1
  });

  serverOwnerStore.set(finalKey, hashToken(newLicenseKey));

  currentKeys.push(finalKey);
  user.serverKeys = currentKeys;
  user.serverKey = finalKey; // Set new server as currently active

  saveDatabaseToDisk();
  saveLicensesToDisk();
  saveServersToDisk();

  logAdminAction("SERVER_SLOT_CREATED", finalKey, user.email, request.ip, `Slot ${currentKeys.length}/${currentSlots}`);

  return {
    success: true,
    message: `Server slot '${finalKey}' created successfully!`,
    serverKey: finalKey,
    licenseKey: newLicenseKey,
    usedSlots: currentKeys.length,
    totalSlots: currentSlots
  };
});

// 12b. Add / Register Custom Non-Bridge Minecraft Server
fastify.post<{
  Body: {
    name: string;
    ip: string;
    port?: number;
    minecraftVersion?: string;
    loader?: string;
    motd?: string;
    serverKey?: string;
  }
}>("/api/v1/user/servers/custom", {
  preHandler: [requireUserAuth]
}, async (request, reply) => {
  const user: User = (request as any).user;
  const { name, ip, port, minecraftVersion, loader, motd, serverKey: requestedKey } = request.body || {};

  if (!name || !ip) {
    return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Server name and IP address are required." });
  }

  const currentSlots = user.serverSlots || 1;
  const currentKeys = user.serverKeys && user.serverKeys.length > 0 ? user.serverKeys : [user.serverKey];

  if (currentKeys.length >= currentSlots || currentKeys.length >= 4) {
    return reply.status(403).send({
      statusCode: 403,
      error: "Slot Limit Reached",
      message: `You have reached your server slot limit (${currentKeys.length}/${currentSlots}). Upgrade your slots to add more servers.`
    });
  }

  let finalKey = "";
  if (requestedKey && requestedKey.trim()) {
    const cleanKey = requestedKey.trim().toLowerCase();
    const validation = validateSubdomainOrKey(cleanKey);
    if (!validation.valid) {
      return reply.status(400).send({ statusCode: 400, error: "Invalid Key", message: validation.error });
    }
    if (isServerKeyClaimed(cleanKey, user.id)) {
      return reply.status(409).send({ statusCode: 409, error: "Conflict", message: `Key '${cleanKey}' is already taken.` });
    }
    finalKey = cleanKey;
  } else {
    finalKey = generateRandomServerKey(isServerKeyClaimed);
  }

  const safeName = sanitizeString(name, 64);
  const safeIp = sanitizeString(ip, 128);
  const safePort = Number(port) || 25565;
  const safeMcVersion = sanitizeString(minecraftVersion || "1.21.1", 32);
  const safeLoader = sanitizeString(loader || "vanilla", 32);
  const safeMotd = sanitizeString(motd || `${safeName} - Custom Minecraft Server`, 128);
  const newLicenseKey = generateLicenseKey(user.sponsored ? "SPONSOR" : "FREE");

  // Create license
  licenseStore.set(newLicenseKey, {
    licenseKey: newLicenseKey,
    tier: user.sponsored ? "SPONSOR" : "FREE",
    ownerEmail: user.email,
    serverKey: finalKey,
    status: "active",
    createdAt: Date.now(),
    notes: `Custom standalone server registered by ${user.email}`
  });

  // Create server entry with active state
  serverStore.set(finalKey, {
    serverKey: finalKey,
    name: safeName,
    ip: safeIp,
    port: safePort,
    version: {
      minecraft: safeMcVersion,
      loader: safeLoader,
      loaderVersion: `${safeMcVersion}-custom`
    },
    status: {
      players: 0,
      maxPlayers: 50,
      motd: safeMotd
    },
    mods: [],
    lastHeartbeat: Date.now(),
    verified: false,
    boosts: 0,
    sponsored: user.sponsored,
    bannerUrl: null,
    links: { store: "", discord: "", website: "" },
    ownerEmail: user.email,
    slotIndex: currentKeys.length + 1
  });

  serverOwnerStore.set(finalKey, hashToken(newLicenseKey));

  currentKeys.push(finalKey);
  user.serverKeys = currentKeys;
  user.serverKey = finalKey;

  saveDatabaseToDisk();
  saveLicensesToDisk();
  saveServersToDisk();

  logAdminAction("CUSTOM_SERVER_ADDED", finalKey, user.email, request.ip, `Registered custom server ${safeIp}:${safePort}`);

  return {
    success: true,
    message: `Custom server '${safeName}' added successfully to your fleet!`,
    serverKey: finalKey,
    licenseKey: newLicenseKey,
    usedSlots: currentKeys.length,
    totalSlots: currentSlots
  };
});

// 13. Select / Switch Active Server Slot
fastify.post<{ Body: { serverKey: string } }>("/api/v1/user/servers/select", {
  preHandler: [requireUserAuth]
}, async (request, reply) => {
  const user: User = (request as any).user;
  const { serverKey } = request.body || {};

  if (!serverKey || !user.serverKeys?.includes(serverKey.trim().toLowerCase())) {
    return reply.status(404).send({ error: "Not Found", message: "Server not found in your owned slots." });
  }

  user.serverKey = serverKey.trim().toLowerCase();
  saveDatabaseToDisk();

  return {
    success: true,
    activeServerKey: user.serverKey
  };
});

// 14. Delete / Release Secondary Server Slot
fastify.delete<{ Params: { serverKey: string } }>("/api/v1/user/servers/:serverKey", {
  preHandler: [requireUserAuth]
}, async (request, reply) => {
  const user: User = (request as any).user;
  const targetKey = sanitizeString(request.params.serverKey, 64).toLowerCase();

  const currentKeys = user.serverKeys || [user.serverKey];
  if (!currentKeys.includes(targetKey)) {
    return reply.status(404).send({ error: "Not Found", message: "Server not found in your slots." });
  }

  if (currentKeys.length <= 1) {
    return reply.status(400).send({ error: "Bad Request", message: "Cannot delete your only remaining primary server slot." });
  }

  // Remove from stores
  serverStore.delete(targetKey);
  serverOwnerStore.delete(targetKey);

  user.serverKeys = currentKeys.filter(k => k !== targetKey);
  if (user.serverKey === targetKey) {
    user.serverKey = user.serverKeys[0] || "";
  }

  saveDatabaseToDisk();
  saveServersToDisk();

  logAdminAction("SERVER_SLOT_DELETED", targetKey, user.email, request.ip, "Released server slot");

  return {
    success: true,
    message: `Server slot '${targetKey}' removed.`,
    activeServerKey: user.serverKey,
    remainingSlots: user.serverKeys.length
  };
});

// 15. User Boost Action
const BOOST_COOLDOWN_MS = 24 * 60 * 60 * 1000;
const MAX_SERVER_BOOSTS = 50;

fastify.post<{ Body: { amount?: number } }>("/api/v1/user/boost", {
  preHandler: [requireUserAuth],
  config: {
    rateLimit: {
      max: 5,
      timeWindow: "1 minute"
    }
  }
}, async (request, reply) => {
  const user: User = (request as any).user;
  const now = Date.now();

  if (user.lastBoostAt && (now - user.lastBoostAt < BOOST_COOLDOWN_MS)) {
    const remainingMs = BOOST_COOLDOWN_MS - (now - user.lastBoostAt);
    const hoursLeft = Math.floor(remainingMs / (60 * 60 * 1000));
    const minutesLeft = Math.ceil((remainingMs % (60 * 60 * 1000)) / (60 * 1000));
    const timeString = hoursLeft > 0 ? `${hoursLeft}h ${minutesLeft}m` : `${minutesLeft}m`;

    return reply.status(429).send({
      success: false,
      error: "Cooldown active",
      message: `Cooldown active: You can only boost once every 24 hours. Next boost in ${timeString}.`,
      remainingMs,
      nextBoostAt: user.lastBoostAt + BOOST_COOLDOWN_MS
    });
  }

  if ((user.boosts || 0) >= MAX_SERVER_BOOSTS) {
    return reply.status(400).send({
      success: false,
      error: "Max boosts reached",
      message: `Maximum boost limit (${MAX_SERVER_BOOSTS} boosts) reached for this server.`
    });
  }

  user.boosts = (user.boosts || 0) + 1;
  user.lastBoostAt = now;

  if (user.boosts >= 10) {
    user.sponsored = true;
    user.serverSlots = Math.max(user.serverSlots || 1, 4); // Sponsor unlocks 4 slots
  }

  const server = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
  if (server) {
    server.boosts = user.boosts;
    server.sponsored = user.sponsored;
  }

  saveDatabaseToDisk();

  return {
    success: true,
    message: `Server boosted successfully! (+1 Boost)`,
    boosts: user.boosts,
    boostCount: user.boosts,
    lastBoostAt: user.lastBoostAt,
    nextBoostAt: user.lastBoostAt + BOOST_COOLDOWN_MS,
    canBoost: false,
    sponsored: user.sponsored
  };
});

// 16. User Settings Action
fastify.post<{ Body: { 
  serverKey?: string;
  subdomain?: string;
  serverName?: string;
  bannerUrl?: string; 
  storeUrl?: string; 
  discordInvite?: string; 
  links?: { store?: string; discord?: string; website?: string } 
} }>("/api/v1/user/settings", { preHandler: [requireUserAuth] }, async (request, reply) => {
  const user: User = (request as any).user;
  const body = request.body || {};

  const requestedSubdomain = body.subdomain || body.serverKey;
  if (requestedSubdomain !== undefined && requestedSubdomain.trim() !== "") {
    const cleanSubdomain = requestedSubdomain.trim().toLowerCase();
    
    if (cleanSubdomain !== user.serverKey.toLowerCase()) {
      const validation = validateSubdomainOrKey(cleanSubdomain);
      if (!validation.valid) {
        return reply.status(400).send({
          statusCode: 400,
          error: "Invalid Subdomain",
          message: validation.error || "Invalid subdomain or server key."
        });
      }

      if (isServerKeyClaimed(cleanSubdomain, user.id)) {
        return reply.status(409).send({
          statusCode: 409,
          error: "Conflict",
          message: `The subdomain or server key '${cleanSubdomain}' is already taken by another account.`
        });
      }

      const oldServer = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
      if (oldServer) {
        serverStore.delete(user.serverKey);
        oldServer.serverKey = cleanSubdomain;
        serverStore.set(cleanSubdomain, oldServer);
      }

      const tokenHash = hashToken(user.licenseKey);
      serverOwnerStore.delete(user.serverKey);
      serverOwnerStore.set(cleanSubdomain, tokenHash);

      // Replace in serverKeys array
      if (user.serverKeys) {
        const idx = user.serverKeys.indexOf(user.serverKey);
        if (idx !== -1) user.serverKeys[idx] = cleanSubdomain;
      }
      user.serverKey = cleanSubdomain;
    }
  }

  if (body.serverName !== undefined) {
    const sanitizedName = sanitizeString(body.serverName, 64);
    if (sanitizedName) {
      const srv = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
      if (srv) {
        srv.name = sanitizedName;
      }
    }
  }

  if (body.bannerUrl !== undefined) {
    user.bannerUrl = sanitizeString(body.bannerUrl, 512);
  }

  const store = body.storeUrl !== undefined ? sanitizeString(body.storeUrl, 256) : (body.links?.store ? sanitizeString(body.links.store, 256) : (user.links?.store || ""));
  const discord = body.discordInvite !== undefined ? sanitizeString(body.discordInvite, 256) : (body.links?.discord ? sanitizeString(body.links.discord, 256) : (user.links?.discord || ""));
  const website = body.links?.website !== undefined ? sanitizeString(body.links.website, 256) : (user.links?.website || "");

  user.links = { store, discord, website };

  const server = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
  if (server) {
    if (user.bannerUrl) server.bannerUrl = user.bannerUrl;
    server.links = user.links;
  }

  saveDatabaseToDisk();
  saveServersToDisk();

  return {
    success: true,
    serverKey: user.serverKey,
    vanityDomain: `${user.serverKey}.${process.env.TUNNEL_PUBLIC_DOMAIN || "realms.sunveil.net"}`,
    bannerUrl: user.bannerUrl,
    storeUrl: user.links.store,
    discordInvite: user.links.discord,
    links: user.links
  };
});

// 17. Regenerate License Key
const handleRegenerateKey = async (request: FastifyRequest) => {
  const user: User = (request as any).user;
  const oldKey = user.licenseKey;

  if (licenseStore.has(oldKey)) {
    const oldLic = licenseStore.get(oldKey)!;
    oldLic.status = "revoked";
    oldLic.revocationReason = "User requested key regeneration";
  }

  user.licenseKey = generateLicenseKey(user.sponsored ? "SPONSOR" : "FREE");

  licenseStore.set(user.licenseKey, {
    licenseKey: user.licenseKey,
    tier: user.sponsored ? "SPONSOR" : "FREE",
    ownerEmail: user.email,
    serverKey: user.serverKey,
    status: "active",
    createdAt: Date.now(),
    notes: "Regenerated user license"
  });

  if (serverStore.has(oldKey)) {
    const srv = serverStore.get(oldKey)!;
    serverStore.delete(oldKey);
    serverStore.set(user.licenseKey, srv);
  }

  saveDatabaseToDisk();
  saveLicensesToDisk();
  saveServersToDisk();

  return {
    success: true,
    licenseKey: user.licenseKey
  };
};

fastify.post("/api/v1/user/license/regenerate", { preHandler: [requireUserAuth] }, handleRegenerateKey);
fastify.post("/api/v1/user/regenerate-key", { preHandler: [requireUserAuth] }, handleRegenerateKey);

// ============================================================================
// 18. AUTOMATED TEBEX STORE WEBHOOK HANDLER (SLOT EXPANSION & SPONSORS)
// ============================================================================
const handleTebexWebhook = async (request: FastifyRequest, reply: FastifyReply) => {
  const body = (request.body || {}) as any;
  const webhookType = body.type || body.event || "";
  const webhookId = body.id || "";

  if (webhookType === "validation.webhook" || webhookType === "validation") {
    console.log(`[Tebex Webhook] Received validation ping from Tebex (ID: ${webhookId})`);
    return reply.status(200).send({ id: webhookId, status: "validated" });
  }

  if (webhookType === "payment.completed" || webhookType === "order.completed" || !webhookType) {
    const subject = body.subject || body;
    const customer = subject.customer || {};
    const email = customer.email || subject.email || "";
    const username = customer.username?.username || customer.username || subject.username || "";
    const products = subject.products || subject.packages || [];
    const transactionId = subject.transaction_id || subject.txn_id || webhookId || "unknown";

    console.log(`[Tebex Webhook] Payment received! TXN: ${transactionId} | Buyer: ${email || username}`);

    let isBoostOrSponsor = false;
    let isSlotExpansion = false;
    let boostBonus = 0;
    let extraSlots = 0;

    for (const prod of products) {
      const prodName = (prod.name || prod.package_name || "").toLowerCase();
      const customData = (prod.custom_data || prod.custom || "").toString().toLowerCase();
      
      if (prodName.includes("slot") || prodName.includes("multi_server") || customData.includes("slot") || customData.includes("server_slots")) {
        isSlotExpansion = true;
        extraSlots += (prod.quantity || 1);
      }
      if (prodName.includes("boost") || prodName.includes("sponsor") || prodName.includes("featured") || prodName.includes("pro")) {
        isBoostOrSponsor = true;
        boostBonus += 25 * (prod.quantity || 1);
        if (prodName.includes("sponsor") || prodName.includes("pro")) {
          isSlotExpansion = true;
          extraSlots = 4; // Unlocks full 4 slots
        }
      }
    }

    let targetUser: User | undefined;
    if (email) targetUser = findUserByIdentifier(email);
    if (!targetUser && username) targetUser = findUserByIdentifier(username);

    if (!targetUser && subject.custom) {
      for (const val of Object.values(subject.custom)) {
        if (typeof val === "string") {
          const found = findUserByIdentifier(val);
          if (found) { targetUser = found; break; }
        }
      }
    }

    if (targetUser) {
      if (isBoostOrSponsor) {
        targetUser.sponsored = true;
        targetUser.boosts = (targetUser.boosts || 0) + (boostBonus || 25);
      }
      if (isSlotExpansion) {
        targetUser.serverSlots = Math.min(4, Math.max(targetUser.serverSlots || 1, (targetUser.serverSlots || 1) + (extraSlots || 1)));
      }

      saveDatabaseToDisk();
      saveServersToDisk();
      logAdminAction("TEBEX_ORDER_PROCESSED", targetUser.email, "TebexWebhook", request.ip, `Slots: ${targetUser.serverSlots} | Boosts: ${targetUser.boosts}`);
    }

    return reply.status(200).send({
      success: true,
      processed: true,
      transactionId,
      matchedUser: targetUser?.email || null,
      serverSlots: targetUser?.serverSlots || null
    });
  }

  return reply.status(200).send({ success: true, event: webhookType });
};

fastify.post("/api/tebex/webhook", handleTebexWebhook);
fastify.post("/api/v1/tebex/webhook", handleTebexWebhook);
fastify.get("/api/tebex/webhook", async () => ({
  status: "active",
  service: "Sunveil Tebex Webhook Receiver",
  time: new Date().toISOString()
}));

// ============================================================================
// 19. HARDENED SECRET ADMIN DASHBOARD & SERVER CONTROL API
// ============================================================================

fastify.post<{ Body: { secretKey?: string; password?: string } }>("/api/v1/admin/auth", {
  config: {
    rateLimit: {
      max: 10,
      timeWindow: "1 minute"
    }
  }
}, async (request, reply) => {
  const clientIp = getClientIp(request);

  // 1. Check IP Lockout
  const lockout = checkAdminIpLockout(clientIp);
  if (lockout.locked) {
    return reply.status(429).send({
      statusCode: 429,
      error: "Too Many Requests",
      message: `Administrative access locked out for your IP (${clientIp}). Try again in ${Math.ceil(lockout.remainingSeconds / 60)} minutes.`,
      remainingSeconds: lockout.remainingSeconds
    });
  }

  const { secretKey, password } = request.body || {};
  const candidate = (secretKey || password || "").trim();

  if (!candidate || !verifyAdminSecret(candidate)) {
    const failState = recordAdminFailedAttempt(clientIp, "failed_admin_login");
    logAdminAction("FAILED_ADMIN_LOGIN", "/api/v1/admin/auth", "anonymous", clientIp, `Invalid master secret (Attempt ${failState.failures})`);

    if (failState.locked) {
      return reply.status(429).send({
        statusCode: 429,
        error: "Too Many Requests",
        message: `Too many failed login attempts. Your IP (${clientIp}) has been locked out for ${Math.ceil(failState.remainingSeconds / 60)} minutes.`,
        remainingSeconds: failState.remainingSeconds
      });
    }

    return reply.status(401).send({
      statusCode: 401,
      error: "Unauthorized",
      message: "Invalid Administrative Secret.",
      attemptsRemaining: Math.max(0, 5 - failState.failures)
    });
  }

  recordAdminSuccess(clientIp);
  const token = generateAdminJWT("root_admin");
  logAdminAction("ADMIN_LOGIN_SUCCESS", "Admin Session", "root_admin", clientIp, "Elevated admin session granted");

  const isHttps = request.protocol === "https" || request.headers["x-forwarded-proto"] === "https";
  reply.setCookie("svl_admin_session", token, {
    path: "/",
    httpOnly: true,
    secure: isHttps || process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 24 * 60 * 60
  });

  return {
    success: true,
    token,
    actor: "root_admin",
    expiresIn: "12 hours"
  };
});

fastify.post("/api/v1/admin/logout", async (request, reply) => {
  reply.clearCookie("svl_admin_session", { path: "/" });
  return { success: true, message: "Admin session cleared." };
});

// Admin Security Management - View Active Lockouts
fastify.get("/api/v1/admin/security/lockouts", { preHandler: [requireAdminAuth] }, async () => {
  const now = Date.now();
  const lockouts = Array.from(adminIpLockoutMap.entries()).map(([ip, state]) => ({
    ip,
    failures: state.failures,
    isLocked: Boolean(state.lockedUntil && now < state.lockedUntil),
    remainingSeconds: state.lockedUntil && now < state.lockedUntil ? Math.ceil((state.lockedUntil - now) / 1000) : 0,
    lastAttempt: state.lastAttempt
  }));
  return { success: true, lockouts };
});

// Admin Security Management - Unblock IP
fastify.post<{ Body: { ip: string } }>("/api/v1/admin/security/unblock", { preHandler: [requireAdminAuth] }, async (request, reply) => {
  const { ip } = request.body || {};
  if (!ip) {
    return reply.status(400).send({ error: "IP address is required." });
  }
  const actor = (request as any).adminActor || "admin";
  const unblocked = unblockAdminIp(ip);
  logAdminAction("ADMIN_IP_UNBLOCK", ip, actor, getClientIp(request), `Manually unblocked by ${actor}`);
  return { success: true, unblocked, ip };
});

fastify.get("/api/v1/admin/overview", { preHandler: [requireAdminAuth] }, async () => {
  const now = Date.now();
  let totalPlayers = 0;
  let onlineServers = 0;
  let bannedServers = 0;

  for (const [, srv] of serverStore.entries()) {
    if (srv.isBanned) {
      bannedServers++;
    }
    const isOnline = Boolean(srv.lastHeartbeat && (now - srv.lastHeartbeat < 90000));
    if (isOnline) {
      onlineServers++;
      totalPlayers += srv.status?.players || 0;
    }
  }

  return {
    stats: {
      totalServers: serverStore.size,
      onlineServers,
      bannedServers,
      totalUsers: userStore.size,
      totalLicenses: licenseStore.size,
      onlinePlayers: totalPlayers,
      systemUptimeSeconds: Math.floor(process.uptime()),
      memoryUsageMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
      nodeVersion: process.version
    }
  };
});

fastify.get("/api/v1/admin/servers", { preHandler: [requireAdminAuth] }, async () => {
  const now = Date.now();
  const list: any[] = [];

  for (const [key, srv] of serverStore.entries()) {
    const tunnel = relayServer.getTunnel(srv.serverKey);
    const isOnline = Boolean((srv.lastHeartbeat && (now - srv.lastHeartbeat < 90000)) || tunnel);
    
    let matchedUser: User | undefined;
    for (const u of userStore.values()) {
      if (u.serverKey === key || (u.serverKeys && u.serverKeys.includes(key)) || u.licenseKey === key) {
        matchedUser = u;
        break;
      }
    }
    if (!matchedUser) {
      for (const lic of licenseStore.values()) {
        if (lic.serverKey === key && lic.ownerEmail) {
          matchedUser = userStore.get(lic.ownerEmail.toLowerCase());
          break;
        }
      }
    }

    const relayHost = `${srv.serverKey.toLowerCase().replace(/[^a-z0-9_-]/g, "")}.realms.sunveil.net`;

    list.push({
      serverKey: srv.serverKey,
      name: srv.name,
      endpoint: `🛡️ ${relayHost}`,
      relayHost,
      ip: "🛡️ Protected Relay",
      port: tunnel ? tunnel.assignedPort : (srv.isCustom ? srv.port : 25565),
      region: srv.region || "EU",
      version: srv.version,
      status: {
        ...srv.status,
        online: isOnline
      },
      online: isOnline,
      modsCount: srv.mods?.length || 0,
      boosts: srv.boosts || 0,
      sponsored: srv.sponsored || false,
      isBanned: Boolean(srv.isBanned),
      banReason: srv.banReason || null,
      bannedAt: srv.bannedAt || null,
      ownerEmail: matchedUser?.email || (srv.isCustom ? "custom_admin" : "unclaimed"),
      ownerId: matchedUser?.id || null,
      trustScore: matchedUser?.trustScore || 85,
      trustLevel: matchedUser?.trustLevel || "TRUSTED",
      serverSlots: matchedUser?.serverSlots || 1,
      hwid: matchedUser?.hwid || "N/A",
      lastHeartbeat: srv.lastHeartbeat || 0,
      performance: srv.performance || null,
      playerList: srv.playerList || []
    });
  }

  return { servers: list };
});

// Admin Prune Offline / Stale Servers
fastify.post("/api/v1/admin/servers/prune-offline", { preHandler: [requireAdminAuth] }, async (request, reply) => {
  const now = Date.now();
  let prunedCount = 0;
  for (const [key, srv] of serverStore.entries()) {
    const tunnel = relayServer.getTunnel(key);
    const isOnline = Boolean(tunnel || (srv.lastHeartbeat && (now - srv.lastHeartbeat < 90000)));
    if (!isOnline) {
      serverStore.delete(key);
      serverOwnerStore.delete(key);
      prunedCount++;
    }
  }
  saveDatabaseToDisk();
  logAdminAction("PRUNE_OFFLINE_SERVERS", `Pruned ${prunedCount} offline servers`, (request as any).adminUser?.email || "Admin", request.ip, `Count: ${prunedCount}`);
  return { success: true, prunedCount, message: `Successfully pruned ${prunedCount} offline ghost servers.` };
});

fastify.post<{ Params: { serverKey: string }; Body: { banned: boolean; reason?: string } }>(
  "/api/v1/admin/servers/:serverKey/ban",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const safeKey = sanitizeString(request.params.serverKey, 64);
    const { banned, reason } = request.body || {};
    const actor = (request as any).adminActor || "admin";

    const srv = serverStore.get(safeKey);
    if (!srv) {
      return reply.status(404).send({ error: "Server not found." });
    }

    srv.isBanned = Boolean(banned);
    srv.banReason = banned ? sanitizeString(reason || "Policy Violation / Prohibited Behavior", 256) : undefined;
    srv.bannedAt = banned ? Date.now() : undefined;

    if (banned) {
      const tunnel = relayServer.getTunnel(safeKey);
      if (tunnel) {
        (tunnel as any).destroy?.();
      }
    }

    for (const u of userStore.values()) {
      if (u.serverKey === safeKey || (u.serverKeys && u.serverKeys.includes(safeKey))) {
        u.isBanned = Boolean(banned);
        u.banReason = srv.banReason;
        u.bannedAt = srv.bannedAt;
        break;
      }
    }

    saveServersToDisk();
    saveDatabaseToDisk();

    logAdminAction(
      banned ? "SERVER_BAN" : "SERVER_UNBAN",
      safeKey,
      actor,
      request.ip,
      banned ? `Reason: ${srv.banReason}` : "Server unbanned and restored"
    );

    return {
      success: true,
      serverKey: safeKey,
      isBanned: srv.isBanned,
      banReason: srv.banReason
    };
  }
);

fastify.delete<{ Params: { serverKey: string } }>(
  "/api/v1/admin/servers/:serverKey",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const safeKey = sanitizeString(request.params.serverKey, 64);
    const actor = (request as any).adminActor || "admin";

    if (!serverStore.has(safeKey)) {
      return reply.status(404).send({ error: "Server not found." });
    }

    serverStore.delete(safeKey);
    serverOwnerStore.delete(safeKey);

    saveServersToDisk();

    logAdminAction("SERVER_DELETE", safeKey, actor, request.ip, "Server purged permanently from network registry");

    return {
      success: true,
      message: `Server '${safeKey}' successfully removed.`
    };
  }
);

// Admin: Update User Server Slots (1 to 4)
fastify.post<{ Params: { userId: string }; Body: { serverSlots: number } }>(
  "/api/v1/admin/users/:userId/slots",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const { userId } = request.params;
    const { serverSlots } = request.body || {};
    const actor = (request as any).adminActor || "admin";

    const user = userIdStore.get(userId) || findUserByIdentifier(userId);
    if (!user) {
      return reply.status(404).send({ error: "User not found." });
    }

    user.serverSlots = Math.min(4, Math.max(1, Number(serverSlots) || 1));
    saveDatabaseToDisk();

    logAdminAction("USER_SLOTS_UPDATED", user.email, actor, request.ip, `New Slots: ${user.serverSlots}`);

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        serverSlots: user.serverSlots
      }
    };
  }
);

// Admin: Update User Trust Score
fastify.post<{ Params: { userId: string }; Body: { trustScore: number; trustLevel?: TrustLevel } }>(
  "/api/v1/admin/users/:userId/trust",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const { userId } = request.params;
    const { trustScore, trustLevel } = request.body || {};
    const actor = (request as any).adminActor || "admin";

    const user = userIdStore.get(userId) || findUserByIdentifier(userId);
    if (!user) {
      return reply.status(404).send({ error: "User not found." });
    }

    user.trustScore = Math.min(100, Math.max(0, Number(trustScore) || 85));
    if (trustLevel) {
      user.trustLevel = trustLevel;
    } else {
      user.trustLevel = user.trustScore >= 85 ? "TRUSTED" : (user.trustScore >= 50 ? "NORMAL" : (user.trustScore >= 25 ? "SUSPICIOUS" : "QUARANTINED"));
    }
    saveDatabaseToDisk();

    logAdminAction("USER_TRUST_UPDATED", user.email, actor, request.ip, `Score: ${user.trustScore} (${user.trustLevel})`);

    return {
      success: true,
      user: {
        id: user.id,
        email: user.email,
        trustScore: user.trustScore,
        trustLevel: user.trustLevel
      }
    };
  }
);

fastify.get("/api/v1/admin/licenses", { preHandler: [requireAdminAuth] }, async () => {
  return { licenses: Array.from(licenseStore.values()) };
});

fastify.post<{ Body: { tier?: LicenseTier; ownerEmail?: string; maxPlayers?: number; notes?: string; customKey?: string } }>(
  "/api/v1/admin/licenses/create",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const { tier = "FREE", ownerEmail, maxPlayers, notes, customKey } = request.body || {};
    const actor = (request as any).adminActor || "admin";

    let key = customKey ? sanitizeString(customKey, 64).toUpperCase() : generateLicenseKey(tier);
    if (licenseStore.has(key)) {
      return reply.status(409).send({ error: "Conflict", message: "License key already exists." });
    }

    const newLic: LicenseEntry = {
      licenseKey: key,
      tier: tier as LicenseTier,
      ownerEmail: ownerEmail ? sanitizeString(ownerEmail, 128).toLowerCase() : undefined,
      status: "active",
      createdAt: Date.now(),
      maxPlayers: maxPlayers ? Math.max(1, Number(maxPlayers)) : undefined,
      notes: notes ? sanitizeString(notes, 256) : `Created by admin ${actor}`
    };

    licenseStore.set(key, newLic);
    saveLicensesToDisk();

    logAdminAction("LICENSE_CREATE", key, actor, request.ip, `Tier: ${tier} | Owner: ${ownerEmail || "None"}`);

    return {
      success: true,
      license: newLic
    };
  }
);

fastify.post<{ Params: { licenseKey: string }; Body: { status: "active" | "revoked" | "banned"; reason?: string } }>(
  "/api/v1/admin/licenses/:licenseKey/revoke",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const key = sanitizeString(request.params.licenseKey, 64).toUpperCase();
    const { status = "revoked", reason } = request.body || {};
    const actor = (request as any).adminActor || "admin";

    const lic = licenseStore.get(key);
    if (!lic) {
      return reply.status(404).send({ error: "License not found." });
    }

    lic.status = status;
    lic.revocationReason = status !== "active" ? sanitizeString(reason || "Admin revocation", 256) : undefined;

    saveLicensesToDisk();

    logAdminAction("LICENSE_STATUS_CHANGE", key, actor, request.ip, `New Status: ${status} | Reason: ${lic.revocationReason || "N/A"}`);

    return {
      success: true,
      license: lic
    };
  }
);

fastify.delete<{ Params: { licenseKey: string } }>(
  "/api/v1/admin/licenses/:licenseKey",
  { preHandler: [requireAdminAuth] },
  async (request, reply) => {
    const key = sanitizeString(request.params.licenseKey, 64).toUpperCase();
    const actor = (request as any).adminActor || "admin";

    if (!licenseStore.has(key)) {
      return reply.status(404).send({ error: "License not found." });
    }

    licenseStore.delete(key);
    saveLicensesToDisk();

    logAdminAction("LICENSE_DELETE", key, actor, request.ip, "License purged from database");

    return {
      success: true,
      message: `License '${key}' deleted.`
    };
  }
);

fastify.get("/api/v1/admin/audit-logs", { preHandler: [requireAdminAuth] }, async () => {
  return { logs: auditLogs.slice(0, 500) };
});

fastify.setNotFoundHandler((request, reply) => {
  if (request.url.startsWith("/api/")) {
    return reply.status(404).send({ error: "Not Found", message: "API endpoint not found" });
  }

  const cleanPath = request.url.split("?")[0] || "";
  if (cleanPath === "/admin" || cleanPath === "/admin-secret" || cleanPath === "/admin-portal") {
    const adminPath = path.join(PUBLIC_DIR, "admin.html");
    if (fs.existsSync(adminPath)) {
      return reply.type("text/html").send(fs.readFileSync(adminPath, "utf8"));
    }
  }

  if (cleanPath === "/dashboard" || cleanPath === "/login" || cleanPath === "/register" || cleanPath === "/servers" || cleanPath === "/connect") {
    const indexPath = path.join(PUBLIC_DIR, "index.html");
    if (fs.existsSync(indexPath)) {
      return reply.type("text/html").send(fs.readFileSync(indexPath, "utf8"));
    }
  }

  const notFoundPath = path.join(PUBLIC_DIR, "404.html");
  if (fs.existsSync(notFoundPath)) {
    return reply.status(404).type("text/html").send(fs.readFileSync(notFoundPath, "utf8"));
  }

  return reply.status(404).send("Page not found");
});

const start = async () => {
  try {
    loadDatabaseFromDisk();
    loadServersFromDisk();

    // Ensure HTTP server runs on port 8080 (or HTTP_PORT), keeping 25565 dedicated for Minecraft TCP SNI relay
    let httpPort = Number(process.env.HTTP_PORT) || 8080;
    if (process.env.PORT && process.env.PORT !== "25565") {
      httpPort = Number(process.env.PORT);
    }
    const host = process.env.HOST || "0.0.0.0";

    await fastify.listen({ port: httpPort, host });
    relayServer.attach(fastify.server);
    console.log(`\n🚀 SVL Master-API & Realms Portal running securely on http://${host}:${httpPort}\n🔒 Admin Secret Portal accessible at /admin\n`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();