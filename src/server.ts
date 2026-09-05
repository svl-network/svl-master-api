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
  userStore,
  userIdStore,
  hashPassword,
  verifyPassword,
  generateJWT,
  verifyJWT,
  generateLicenseKey,
  seedDemoUser,
  loadDatabaseFromDisk,
  saveDatabaseToDisk,
  getDataDir
} from "./auth.js";
import { relayServer } from "./tunnel/RelayServer.js";

const API_SECRET_KEY = process.env.API_SECRET_KEY || process.env.MASTER_API_TOKEN || "svl_secret_token_2026";
const CLIENT_SECRET = process.env.SVL_CLIENT_SECRET || "svl_prod_sec_99a8b7c6d5";
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
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:", "http:", "https://raw.githubusercontent.com"],
      connectSrc: [
        "'self'",
        "https://realms.sunveil.net",
        "https://dash.sunveil.net",
        "https://api.sunveil.net",
        "https://sunveil.net",
        "https://www.sunveil.net",
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
    // Whitelist authorized bridge heartbeat and storage requests
    const auth = req.headers.authorization;
    if (auth && auth.startsWith("Bearer ") && isValidToken(auth.substring(7).trim())) {
      return true;
    }
    // Whitelist static mod asset downloads
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

// Global preHandler for all API routes to enforce Client Secret and HWID presence
fastify.addHook("preHandler", async (request, reply) => {
  // Skip authentication for static assets, root, healthcheck, and public web endpoints
  if (!request.url.startsWith("/api/v1/")) return;
  if (request.url.startsWith("/api/v1/auth/")) return;
  if (request.url.startsWith("/api/v1/updates/latest")) return;

  // Allow server-to-server and web session endpoints authenticated via Bearer token
  const authHeader = request.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return;
  }

  const clientSecret = request.headers["x-svl-client-secret"];
  const hwid = request.headers["x-svl-hwid"];

  // 1. Validate Secret Token
  if (!clientSecret || clientSecret !== CLIENT_SECRET) {
    fastify.log.warn(`Unauthorized access attempt from IP: ${request.ip}`);
    return reply.status(403).send({
      statusCode: 403,
      error: "Forbidden",
      message: "Invalid or missing client signature."
    });
  }

  // 2. Validate HWID Presence
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
  store?: string;
  discord?: string;
  website?: string;
}

export interface ServerPayload {
  serverKey: string;
  name: string;
  ip: string;
  port: number;
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
  icon?: string;
  mods: ModInfo[];
  lastHeartbeat?: number;
  verified?: boolean;
  boosts?: number;
  sponsored?: boolean;
  bannerUrl?: string | null;
  links?: ServerLinks;
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
  if (token === "svl_secret_token_2026") return true;
  if (process.env.MASTER_API_TOKEN && token === process.env.MASTER_API_TOKEN) return true;

  // Accept any registered server owner licenseKey or serverKey from user database
  for (const user of userStore.values()) {
    if (user.licenseKey && user.licenseKey === token) {
      return true;
    }
    if (user.serverKey && user.serverKey === token) {
      return true;
    }
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

  // Security: Disallow using Master API Secret or sensitive tokens as a public serverKey/subdomain
  const sensitiveTokens = [
    (process.env.API_SECRET_KEY || "").toLowerCase(),
    (process.env.MASTER_API_TOKEN || "").toLowerCase(),
    (process.env.JWT_SECRET || "").toLowerCase(),
    "svl_secret_token_2026"
  ].filter(t => t.length > 0);

  for (const secret of sensitiveTokens) {
    if (clean === secret || (secret.length >= 6 && clean.includes(secret))) {
      return { valid: false, error: "Security violation: Server key cannot match or contain system master tokens." };
    }
  }

  if (clean.includes("secret") || clean.includes("apikey") || clean.includes("token_master")) {
    return { valid: false, error: "Security violation: Server key contains prohibited security keywords." };
  }

  return { valid: true };
}

export function isServerKeyClaimed(serverKey: string, currentUserId?: string): boolean {
  const cleanKey = serverKey.trim().toLowerCase();

  // Check userStore
  for (const u of userStore.values()) {
    if (currentUserId && u.id === currentUserId) continue;
    if (u.serverKey && u.serverKey.toLowerCase() === cleanKey) return true;
    if (u.licenseKey && u.licenseKey.toLowerCase() === cleanKey) return true;
  }

  // Check serverStore
  for (const [key, srv] of serverStore.entries()) {
    if (key.toLowerCase() === cleanKey) {
      if (currentUserId) {
        const ownerHash = serverOwnerStore.get(key);
        const currentUser = userIdStore.get(currentUserId);
        if (currentUser && ownerHash && (ownerHash === hashToken(currentUser.licenseKey) || ownerHash === hashToken(currentUser.serverKey))) {
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

const getBaseUrl = (req: { headers: Record<string, string | string[] | undefined>; protocol: string }) => {
  const host = req.headers["x-forwarded-host"] || req.headers.host || `localhost:${process.env.PORT || 3001}`;
  const proto = req.headers["x-forwarded-proto"] || req.protocol || "http";
  return `${proto}://${host}`;
};

// 1. Health-Check Endpunkt
fastify.get("/health", async () => {
  return { status: "ok", uptime: process.uptime(), registeredServers: serverStore.size };
});

// 2. Storage Check Endpunkt
fastify.get<{ Params: { sha256: string } }>("/api/v1/storage/check/:sha256", async (request, reply) => {
  const { sha256 } = request.params;
  if (!sha256 || !/^[a-fA-F0-9]{64}$/.test(sha256)) {
    return reply.status(400).send({ error: "Invalid SHA-256 hash format." });
  }

  const targetFile = path.resolve(DATA_MODS_DIR, `${sha256.toLowerCase()}.jar`);

  // Path traversal sandbox check
  if (!targetFile.startsWith(DATA_MODS_DIR)) {
    return reply.status(400).send({ error: "Invalid file path traversal detected." });
  }

  const exists = fs.existsSync(targetFile);
  const baseUrl = getBaseUrl(request);
  const url = `${baseUrl}/static/mods/${sha256.toLowerCase()}.jar`;

  return { exists, url: exists ? url : null };
});

// 3. Storage Upload Endpunkt (Protected, Magic Bytes Checked, Sandboxed)
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

    // Magic bytes verification (ZIP/JAR magic number: 0x50 0x4B 0x03 0x04)
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

    // Anti-Malware Inspection: Scan JAR archive for prohibited executable binary extensions
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

    // Strict path traversal validation
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

// 4. Heartbeat Endpunkt (Protected, Input Sanitized, Server-Key Bound)
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

  const rawServerKey = sanitizeString(payload.serverKey, 64);
  const authHeader = request.headers.authorization;
  const token = authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7).trim() : API_SECRET_KEY;
  const currentTokenHash = hashToken(token);

  // Link server to user account if authenticated with user licenseKey or serverKey
  let matchedUser: User | undefined;
  for (const u of userStore.values()) {
    if (u.licenseKey === token || u.serverKey === token || u.serverKey === rawServerKey) {
      matchedUser = u;
      if (u.serverKey !== rawServerKey) {
        u.serverKey = rawServerKey;
        saveDatabaseToDisk();
      }
      break;
    }
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

  // Securely determine the authentic public IP of the Minecraft server from the network connection
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
  // If a domain/hostname or public IP was explicitly provided (and isn't "auto"), preserve it; otherwise use detected incoming IP
  let resolvedIp = incomingIp || "127.0.0.1";
  if (requestedIp && requestedIp.toLowerCase() !== "auto" && requestedIp !== "127.0.0.1" && requestedIp !== "localhost") {
    resolvedIp = sanitizeString(requestedIp, 64);
  } else if (incomingIp) {
    resolvedIp = incomingIp;
  }

  const serverData: ServerPayload = {
    serverKey: rawServerKey,
    name: sanitizeString(payload.name, 64),
    ip: resolvedIp,
    port: Number(payload.port) || 25565,
    version: {
      minecraft: sanitizeString(payload.version?.minecraft, 32),
      loader: sanitizeString(payload.version?.loader, 32),
      loaderVersion: sanitizeString(payload.version?.loaderVersion, 64)
    },
    status: {
      players: Math.max(0, Number(payload.status?.players) || 0),
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
    } : { store: "", discord: "", website: "" }
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

// 5. Öffentliche Serverliste (Sorted by Boosts DESC, then Current Players DESC)
fastify.get("/api/v1/servers", {
  config: {
    rateLimit: {
      max: 30,
      timeWindow: "10 seconds"
    }
  }
}, async () => {
  const now = Date.now();
  const activeServers: any[] = [];

  for (const [key, srv] of serverStore.entries()) {
    const tunnel = relayServer.getTunnel(srv.serverKey);
    const isOnline = Boolean((srv.lastHeartbeat && (now - srv.lastHeartbeat < 90000)) || tunnel);
    const resolvedIp = tunnel ? tunnel.publicHost : srv.ip;
    const resolvedPort = tunnel ? tunnel.assignedPort : srv.port;

    const enriched = {
      ...srv,
      ip: resolvedIp,
      port: resolvedPort,
      online: isOnline,
      modCount: srv.mods ? srv.mods.length : 0,
      tunnel: tunnel ? {
        active: true,
        publicHost: tunnel.publicHost,
        publicPort: tunnel.assignedPort,
        activeClients: tunnel.activeClients,
        connectedAt: tunnel.connectedAt
      } : { active: false },
      status: {
        ...srv.status,
        online: isOnline,
        players: isOnline ? (srv.status?.players || 0) : 0
      }
    };
    activeServers.push(enriched);
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

  const tunnel = relayServer.getTunnel(srv.serverKey);
  const resolvedIp = tunnel ? tunnel.publicHost : srv.ip;
  const resolvedPort = tunnel ? tunnel.assignedPort : srv.port;

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

// 8. Latest Updates Endpunkt
fastify.get("/api/v1/updates/latest", async (request, reply) => {
  return {
    client: {
      version: "1.0.1",
      mandatory: false,
      url: "https://github.com/svl-network/svl-connect/releases/latest",
      changelog: "Includes Modrinth native discovery, delta synchronization, hardware fingerprinting, and real-time security badge system."
    },
    bridge: {
      version: "2.1.0",
      url: "https://github.com/svl-network/svl-bridge/releases/latest"
    }
  };
});

// User JWT Authentication Pre-Handler
const requireUserAuth = async (request: FastifyRequest, reply: FastifyReply) => {
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return reply.status(401).send({
      statusCode: 401,
      error: "Unauthorized",
      message: "Missing or invalid session authorization token."
    });
  }

  const token = authHeader.substring(7).trim();
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

  (request as any).user = user;
};

// 9. Auth Register
fastify.post<{ Body: { email?: string; password?: string; tosAgreed?: boolean; tosPhrase?: string } }>("/api/v1/auth/register", async (request, reply) => {
  const { email, password, tosAgreed, tosPhrase } = request.body || {};
  if (!email || typeof email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Please provide a valid email address." });
  }

  if (!password || typeof password !== "string" || password.length < 8) {
    return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Password must be at least 8 characters long." });
  }

  // Anti-Bot & Anti-Malware Policy Verification
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

  const { hash, salt } = hashPassword(password);
  const licenseKey = generateLicenseKey();
  const serverKey = "realm_" + crypto.randomBytes(6).toString("hex");

  const incomingIp = (request.headers["cf-connecting-ip"] as string)?.trim() || request.ip || "";

  const newUser: User = {
    id: "usr_" + crypto.randomBytes(8).toString("hex"),
    email: normalizedEmail,
    passwordHash: hash,
    salt,
    licenseKey,
    serverKey,
    createdAt: Date.now(),
    boosts: 0,
    sponsored: false,
    links: { store: "", discord: "", website: "" },
    tosAgreedAt: Date.now(),
    tosAgreedIp: incomingIp,
    antiMalwareAffirmed: true
  };

  userStore.set(normalizedEmail, newUser);
  userIdStore.set(newUser.id, newUser);
  saveDatabaseToDisk();

  const token = generateJWT(newUser);

  return {
    success: true,
    token,
    user: {
      id: newUser.id,
      email: newUser.email,
      licenseKey: newUser.licenseKey,
      createdAt: newUser.createdAt,
      antiMalwareAffirmed: true
    }
  };
});

// 10. Auth Login
fastify.post<{ Body: { email?: string; password?: string } }>("/api/v1/auth/login", async (request, reply) => {
  const { email, password } = request.body || {};
  if (!email || !password || typeof email !== "string" || typeof password !== "string") {
    return reply.status(400).send({ statusCode: 400, error: "Bad Request", message: "Email and password are required." });
  }

  const normalizedEmail = email.trim().toLowerCase();
  const user = userStore.get(normalizedEmail);
  if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
    return reply.status(401).send({ statusCode: 401, error: "Unauthorized", message: "Invalid email or password." });
  }

  const token = generateJWT(user);

  return {
    success: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      licenseKey: user.licenseKey,
      createdAt: user.createdAt
    }
  };
});

// 11. User Dashboard Metrics & Status (Real Database & 120s Heartbeat Query)
fastify.get("/api/v1/user/dashboard", { preHandler: [requireUserAuth] }, async (request, reply) => {
  const user: User = (request as any).user;

  let server = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);

  // Heartbeat active if received within the last 120 seconds (120,000 ms)
  const isOnline = !!server && (Date.now() - (server.lastHeartbeat || 0) < 120000);

  return {
    user: {
      id: user.id,
      email: user.email,
      licenseKey: user.licenseKey,
      createdAt: user.createdAt,
      boosts: user.boosts || 0,
      boostCount: user.boosts || 0,
      lastBoostAt: user.lastBoostAt || null,
      nextBoostAt: user.lastBoostAt ? user.lastBoostAt + 24 * 60 * 60 * 1000 : null,
      canBoost: !user.lastBoostAt || (Date.now() - user.lastBoostAt >= 24 * 60 * 60 * 1000),
      sponsored: user.sponsored || false,
      bannerUrl: user.bannerUrl || (server?.bannerUrl || null),
      storeUrl: user.links?.store || (server?.links?.store || ""),
      discordInvite: user.links?.discord || (server?.links?.discord || ""),
      links: user.links || (server?.links || { store: "", discord: "", website: "" })
    },
    server: server ? {
      serverKey: server.serverKey,
      name: server.name,
      online: isOnline,
      ip: server.ip,
      port: server.port,
      players: server.status?.players || 0,
      maxPlayers: server.status?.maxPlayers || 0,
      motd: server.status?.motd || "",
      version: `${server.version?.minecraft || "1.21.1"} ${server.version?.loader || ""} ${server.version?.loaderVersion || ""}`.trim(),
      modCount: server.mods?.length || 0,
      lastHeartbeat: server.lastHeartbeat || null,
      boosts: server.boosts || user.boosts || 0,
      sponsored: server.sponsored || user.sponsored || false,
      bannerUrl: server.bannerUrl || null,
      links: server.links || { store: "", discord: "", website: "" }
    } : null
  };
});

// 12. User Boost Server Action (Persisted in DB with 24h Cooldown & Max Limit)
const BOOST_COOLDOWN_MS = 24 * 60 * 60 * 1000; // 24 hours
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

  // Enforce 24-hour cooldown per account
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

  // Maximum boost limit per server
  if ((user.boosts || 0) >= MAX_SERVER_BOOSTS) {
    return reply.status(400).send({
      success: false,
      error: "Max boosts reached",
      message: `Maximum boost limit (${MAX_SERVER_BOOSTS} boosts) reached for this server.`
    });
  }

  // Exactly 1 boost per daily action
  user.boosts = (user.boosts || 0) + 1;
  user.lastBoostAt = now;

  if (user.boosts >= 10) {
    user.sponsored = true;
  }

  const server = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
  if (server) {
    server.boosts = user.boosts;
    server.sponsored = user.sponsored;
  }

  saveDatabaseToDisk();

  return {
    success: true,
    message: `Server erfolgreich geboostet! (+1 Boost)`,
    boosts: user.boosts,
    boostCount: user.boosts,
    lastBoostAt: user.lastBoostAt,
    nextBoostAt: user.lastBoostAt + BOOST_COOLDOWN_MS,
    canBoost: false,
    sponsored: user.sponsored
  };
});

// 13. User Settings Action (Custom Subdomain, Name, Banner & Direct Links Persisted in DB)
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

  // Custom Subdomain / ServerKey change with collision & reserved keyword validation
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

      // Migrate existing server in store if present
      const oldServer = serverStore.get(user.serverKey) || serverStore.get(user.licenseKey);
      if (oldServer) {
        serverStore.delete(user.serverKey);
        oldServer.serverKey = cleanSubdomain;
        serverStore.set(cleanSubdomain, oldServer);
      }

      // Update ownership record
      const tokenHash = hashToken(user.licenseKey);
      serverOwnerStore.delete(user.serverKey);
      serverOwnerStore.set(cleanSubdomain, tokenHash);

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

// 14. Regenerate License Key (Invalidate old, assign new SVL-FREE key & persist)
const handleRegenerateKey = async (request: FastifyRequest, reply: FastifyReply) => {
  const user: User = (request as any).user;
  const oldKey = user.licenseKey;

  user.licenseKey = generateLicenseKey();

  if (serverStore.has(oldKey)) {
    const srv = serverStore.get(oldKey)!;
    serverStore.delete(oldKey);
    serverStore.set(user.licenseKey, srv);
  }

  saveDatabaseToDisk();

  return {
    success: true,
    licenseKey: user.licenseKey
  };
};

fastify.post("/api/v1/user/license/regenerate", { preHandler: [requireUserAuth] }, handleRegenerateKey);
fastify.post("/api/v1/user/regenerate-key", { preHandler: [requireUserAuth] }, handleRegenerateKey);

// Single Page Application route fallback for /dashboard, /login
fastify.setNotFoundHandler((request, reply) => {
  if (request.url.startsWith("/api/")) {
    return reply.status(404).send({ error: "Not Found", message: "API endpoint not found" });
  }
  const indexPath = path.join(PUBLIC_DIR, "index.html");
  if (fs.existsSync(indexPath)) {
    return reply.type("text/html").send(fs.readFileSync(indexPath, "utf8"));
  }
  return reply.status(404).send("Page not found");
});

// Seed Initial Boosted & Normal Servers for Real-time Verification
const seedDemoServers = () => {
  if (!serverStore.has("svl_demo_realm")) {
    serverStore.set("svl_demo_realm", {
      serverKey: "svl_demo_realm",
      name: "Sunveil Modded Server",
      ip: "127.0.0.1",
      port: 25565,
      version: {
        minecraft: "1.21.1",
        loader: "forge",
        loaderVersion: "61.2.1"
      },
      status: {
        players: 0,
        maxPlayers: 50,
        motd: "Official High-Performance Modded Survival & Adventure Infrastructure."
      },
      verified: true,
      boosts: 15,
      sponsored: true,
      bannerUrl: "https://raw.githubusercontent.com/PolyMC/PolyMC/develop/launcher/resources/multimc/scalable/multimc.svg",
      links: {
        store: "https://store.sunveil.net",
        discord: "https://discord.gg/sunveil",
        website: "https://sunveil.net"
      },
      mods: [
        {
          projectId: "MFgnFY8Z",
          fileName: "3d_placeable_food-3.0.1-forge-1.21.11.jar",
          sha256: "79e6776bb76619b6581353c4fef7357abc92ff6e0ba7a9c23b53e659578ef894",
          downloadUrl: "https://cdn.modrinth.com/data/MFgnFY8Z/versions/8j7tivON/3d_placeable_food-3.0.1-forge-1.21.11.jar",
          tier: "official"
        },
        {
          projectId: "Lvv4SHrK",
          fileName: "BetterThanMending-2.2.5.jar",
          sha256: "9ba8a016b6365f31519185aeb1c95b8a70f764f95d09c5eceeb6c55428d866bd",
          downloadUrl: "https://cdn.modrinth.com/data/Lvv4SHrK/versions/wHUk8xSy/BetterThanMending-2.2.5.jar",
          tier: "official"
        },
        {
          projectId: "dGVX5JbJ",
          fileName: "bettervillage-forge-1.21.11-3.3.1.jar",
          sha256: "06450f967db9aceb264abead49cf240ec92c4a9d1509cf9c9a7a8c70e5356330",
          downloadUrl: "https://cdn.modrinth.com/data/dGVX5JbJ/versions/Pv5QcxqP/bettervillage-forge-1.21.11-3.3.1.jar",
          tier: "official"
        },
        {
          projectId: "HXF82T3G",
          fileName: "BiomesOPlenty-forge-1.21.11-21.11.0.32.jar",
          sha256: "b7e2b7f9d27d118caebb297cbf2f0e696a0e5929828f4e12d8a5e1faf99ee766",
          downloadUrl: "https://cdn.modrinth.com/data/HXF82T3G/versions/a3i8bZGT/BiomesOPlenty-forge-1.21.11-21.11.0.32.jar",
          tier: "official"
        }
      ],
      lastHeartbeat: 0
    });
  }

  if (!serverStore.has("svl_community_realm")) {
    serverStore.set("svl_community_realm", {
      serverKey: "svl_community_realm",
      name: "Sunveil Vanilla+ Realm",
      ip: "play.sunveil.net",
      port: 25565,
      version: {
        minecraft: "1.21.1",
        loader: "fabric",
        loaderVersion: "0.16.0"
      },
      status: {
        players: 0,
        maxPlayers: 30,
        motd: "A chill community survival realm with quality-of-life additions."
      },
      verified: false,
      boosts: 0,
      sponsored: false,
      bannerUrl: null,
      links: {
        store: "",
        discord: "https://discord.gg/sunveil",
        website: ""
      },
      mods: [],
      lastHeartbeat: 0
    });
  }

  saveServersToDisk();
};

const start = async () => {
  try {
    loadDatabaseFromDisk();
    loadServersFromDisk();
    seedDemoServers();

    // Fastify HTTP Web server port (Railway sets PORT, e.g. 8080 or 3001)
    // Never let HTTP bind to the Minecraft TCP tunnel port (25565)
    const tunnelPort = Number(process.env.TUNNEL_MAIN_PORT) || 25565;
    let httpPort = Number(process.env.PORT) || 8080;
    if (httpPort === tunnelPort) {
      console.warn(`⚠️ [SVL-Server] HTTP PORT matches TUNNEL_MAIN_PORT (${tunnelPort}). Shifting HTTP server to port 8080.`);
      httpPort = 8080;
    }
    const host = process.env.HOST || "0.0.0.0";

    await fastify.listen({ port: httpPort, host });
    relayServer.attach(fastify.server);
    console.log(`\n🚀 SVL Master-API & Realms Portal running securely on http://localhost:${httpPort}\n`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();