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

const getDbPath = (): string => {
  const localDataDir = path.resolve(APP_ROOT, "data");
  if (!fs.existsSync(localDataDir)) {
    fs.mkdirSync(localDataDir, { recursive: true });
  }
  return path.resolve(localDataDir, "database.json");
};

const DB_FILE = getDbPath();

export const getJwtSecret = (): string => {
  return process.env.JWT_SECRET || process.env.API_SECRET_KEY || "svl_jwt_realm_secret_2026_supersecure";
};

export interface User {
  id: string;
  email: string;
  passwordHash: string;
  salt: string;
  licenseKey: string;
  serverKey: string;
  createdAt: number;
  boosts: number;
  lastBoostAt?: number;
  sponsored: boolean;
  bannerUrl?: string;
  links?: {
    store?: string;
    discord?: string;
    website?: string;
  };
}

export const userStore = new Map<string, User>(); // email -> User
export const userIdStore = new Map<string, User>(); // id -> User

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
  } catch (err) {
    console.error("Failed to save database to disk:", err);
  }
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
          userStore.set(u.email.toLowerCase(), u);
          userIdStore.set(u.id, u);
        }
      }
    }
  } catch (err) {
    console.error("Failed to load database from disk:", err);
  }
  // Ensure demo user is seeded
  seedDemoUser();
  saveDatabaseToDisk();
};

/**
 * Generates a cryptographically strong license key in SVL format (SVL-FREE-XXXX-XXXX)
 */
export const generateLicenseKey = (): string => {
  const p1 = crypto.randomBytes(2).toString("hex").toUpperCase();
  const p2 = crypto.randomBytes(2).toString("hex").toUpperCase();
  return `SVL-FREE-${p1}-${p2}`;
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
 * Verifies and decodes a JWT token
 */
export const verifyJWT = (token: string): { sub: string; email: string; licenseKey: string } | null => {
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
  const email = (process.env.DEMO_USER_EMAIL || "developer@sunveil.net").toLowerCase();
  const password = process.env.DEMO_USER_PASSWORD || "SunveilDev2026!";
  const defaultLicense = process.env.DEMO_USER_LICENSE || "SVL-FREE-7A9B-4D2E";

  if (!userStore.has(email)) {
    const { hash, salt } = hashPassword(password);
    const user: User = {
      id: "usr_developer_sunveil",
      email,
      passwordHash: hash,
      salt,
      licenseKey: defaultLicense,
      serverKey: "svl_demo_realm",
      createdAt: Date.now() - 30 * 24 * 3600 * 1000,
      boosts: 15,
      sponsored: true,
      bannerUrl: "https://raw.githubusercontent.com/PolyMC/PolyMC/develop/launcher/resources/multimc/scalable/multimc.svg",
      links: {
        store: "https://store.sunveil.net",
        discord: "https://discord.gg/sunveil",
        website: "https://sunveil.net"
      }
    };
    userStore.set(email, user);
    userIdStore.set(user.id, user);
  }
};
