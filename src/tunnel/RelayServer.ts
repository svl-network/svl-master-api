/*
 * Copyright (c) 2026 Sunveil Network. All rights reserved.
 *
 * PROPRIETARY & CONFIDENTIAL
 *
 * This file is part of Sunveil Connect and the Sunveil Bridge.
 * Unauthorized copying of this file, via any medium, is strictly prohibited.
 */

import { WebSocketServer, WebSocket } from "ws";
import type { IncomingMessage } from "node:http";
import net from "node:net";
import crypto from "node:crypto";
import { isValidToken } from "../server.js";

export interface ActiveTunnel {
  serverKey: string;
  assignedPort: number;
  publicHost: string;
  connectedAt: number;
  bytesReceived: number;
  bytesSent: number;
  activeClients: number;
  ws: WebSocket;
  clientSockets: Map<number, net.Socket>;
  tcpServer?: net.Server;
}

// Packet Types for Multiplexed Tunnel
const PKT_OPEN = 0x01;
const PKT_DATA = 0x02;
const PKT_CLOSE = 0x03;
const PKT_PING = 0x04;
const PKT_PONG = 0x05;

// Security Limits & Anti-Abuse
const MAX_PACKET_SIZE = 2 * 1024 * 1024; // 2 MB max packet size
const MAX_CONCURRENT_CLIENTS_PER_TUNNEL = 100;
const MAX_CONN_PER_IP_WINDOW = 40; // Max 40 connection handshakes per minute per IP
const RATE_WINDOW_MS = 60 * 1000;

/**
 * Reads a Minecraft VarInt from a buffer at a given offset
 */
function readVarInt(buffer: Buffer, offset: number): { value: number; bytesRead: number } | null {
  let value = 0;
  let bytesRead = 0;
  let currentByte = 0;

  do {
    if (offset + bytesRead >= buffer.length) return null;
    const b = buffer[offset + bytesRead];
    if (b === undefined) return null;
    currentByte = b;
    value |= (currentByte & 0x7f) << (bytesRead * 7);
    bytesRead++;
    if (bytesRead > 5) return null; // Invalid VarInt
  } while ((currentByte & 0x80) !== 0);

  return { value, bytesRead };
}

/**
 * Writes a Minecraft VarInt into a buffer
 */
function writeVarInt(value: number): Buffer {
  const bytes: number[] = [];
  let val = value;
  do {
    let temp = val & 0x7f;
    val >>>= 7;
    if (val !== 0) {
      temp |= 0x80;
    }
    bytes.push(temp);
  } while (val !== 0);
  return Buffer.from(bytes);
}

/**
 * Parsed Minecraft Handshake details
 */
interface MinecraftHandshake {
  valid: boolean;
  hostname: string;
  port: number;
  nextState: number; // 1 = Status/Ping, 2 = Login
  protocolVersion: number;
}

/**
 * Strict Minecraft Protocol Handshake Parser & Validator
 */
function parseMinecraftHandshake(buffer: Buffer): MinecraftHandshake | null {
  if (!buffer || buffer.length < 2) return null;

  // Legacy Minecraft Ping format (1.6 and below)
  if (buffer[0] === 0xFE) {
    return { valid: true, hostname: "", port: 25565, nextState: 1, protocolVersion: 0 };
  }

  let offset = 0;
  const pktLen = readVarInt(buffer, offset);
  if (!pktLen || pktLen.value <= 0 || pktLen.value > 1024) return null;
  offset += pktLen.bytesRead;

  const pktId = readVarInt(buffer, offset);
  if (!pktId || pktId.value !== 0x00) return null; // Handshake packet ID MUST be 0x00
  offset += pktId.bytesRead;

  const protocolVersion = readVarInt(buffer, offset);
  if (!protocolVersion) return null;
  offset += protocolVersion.bytesRead;

  const hostLength = readVarInt(buffer, offset);
  if (!hostLength || hostLength.value < 0 || hostLength.value > 255) return null;
  offset += hostLength.bytesRead;

  if (buffer.length < offset + hostLength.value + 2) return null;

  let rawHost = buffer.subarray(offset, offset + hostLength.value).toString("utf8");
  // Clean up Forge/FML tags (e.g. "server.domain.com\0FML\0")
  if (rawHost.includes("\0")) {
    rawHost = rawHost.split("\0")[0] || "";
  }
  rawHost = rawHost.toLowerCase().trim();
  if (rawHost.endsWith(".")) {
    rawHost = rawHost.slice(0, -1);
  }

  offset += hostLength.value;
  const port = buffer.readUInt16BE(offset);
  offset += 2;

  const nextState = readVarInt(buffer, offset);
  if (!nextState || (nextState.value !== 1 && nextState.value !== 2)) return null;

  return {
    valid: true,
    hostname: rawHost,
    port,
    nextState: nextState.value,
    protocolVersion: protocolVersion.value
  };
}

/**
 * Creates a Minecraft disconnect packet for players attempting to join an offline or unknown realm
 */
function createDisconnectPacket(message: string): Buffer {
  const jsonPayload = JSON.stringify({
    text: `§c[Sunveil Network] §f${message}`,
    color: "red"
  });
  const jsonBuf = Buffer.from(jsonPayload, "utf8");
  const jsonLenBuf = writeVarInt(jsonBuf.length);
  const packetIdBuf = writeVarInt(0x00); // Disconnect (Login)

  const packetContent = Buffer.concat([packetIdBuf, jsonLenBuf, jsonBuf]);
  const packetLenBuf = writeVarInt(packetContent.length);

  return Buffer.concat([packetLenBuf, packetContent]);
}

/**
 * Creates a Minecraft server list ping response for status requests to unknown/offline realms
 */
function createStatusResponsePacket(hostname: string): Buffer {
  const statusPayload = JSON.stringify({
    version: { name: "Sunveil Relay", protocol: 767 },
    players: { max: 0, online: 0 },
    description: { text: `§eSunveil Realm §7(${hostname}) §c[Offline]\n§7Start your server with the SVL-Bridge plugin.` }
  });
  const jsonBuf = Buffer.from(statusPayload, "utf8");
  const jsonLenBuf = writeVarInt(jsonBuf.length);
  const packetIdBuf = writeVarInt(0x00); // Status Response

  const packetContent = Buffer.concat([packetIdBuf, jsonLenBuf, jsonBuf]);
  const packetLenBuf = writeVarInt(packetContent.length);

  return Buffer.concat([packetLenBuf, packetContent]);
}

export class RelayServer {
  private wss: WebSocketServer | null = null;
  private activeTunnels = new Map<string, ActiveTunnel>(); // serverKey -> ActiveTunnel
  private portToTunnel = new Map<number, string>(); // port -> serverKey

  // SNI Central Relay on Standard Minecraft Port (25565)
  private centralServer: net.Server | null = null;
  private centralPort = Number(process.env.TUNNEL_MAIN_PORT) || 25565;
  private publicDomain = process.env.TUNNEL_PUBLIC_DOMAIN || "realms.sunveil.net";

  // Dedicated Port Pool (Fallback)
  private minPort = Number(process.env.TUNNEL_PORT_MIN) || 25600;
  private maxPort = Number(process.env.TUNNEL_PORT_MAX) || 25700;
  private connectionCounter = 1;

  // Anti-Botting and Flood Protection
  private ipConnectionHistory = new Map<string, number[]>(); // IP -> timestamps[]

  constructor() {
    // Periodic cleanup of IP rate limiting history every 2 minutes
    setInterval(() => {
      const now = Date.now();
      for (const [ip, timestamps] of this.ipConnectionHistory.entries()) {
        const filtered = timestamps.filter(t => now - t < RATE_WINDOW_MS);
        if (filtered.length === 0) {
          this.ipConnectionHistory.delete(ip);
        } else {
          this.ipConnectionHistory.set(ip, filtered);
        }
      }
    }, 2 * 60 * 1000);

    // Initialize the Central SNI Router on standard Minecraft port (25565)
    this.startCentralRouter();
  }

  /**
   * Starts the central hostname-based Minecraft TCP Router on port 25565
   */
  private startCentralRouter() {
    this.centralServer = net.createServer((clientSocket) => {
      const clientIp = clientSocket.remoteAddress || "unknown";

      if (this.isIpRateLimited(clientIp)) {
        clientSocket.destroy();
        return;
      }

      let isHandshakeHandled = false;
      let handshakeBuffer = Buffer.alloc(0);

      clientSocket.on("data", (chunk: Buffer) => {
        if (isHandshakeHandled) return;

        if (chunk.length > MAX_PACKET_SIZE) {
          clientSocket.destroy();
          return;
        }

        handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);
        const handshake = parseMinecraftHandshake(handshakeBuffer);

        if (!handshake) {
          if (handshakeBuffer.length > 1024) {
            clientSocket.destroy();
          }
          return; // Wait for full packet
        }

        isHandshakeHandled = true;

        // Resolve target tunnel by requested hostname/subdomain
        const tunnel = this.findTunnelByHost(handshake.hostname);

        if (!tunnel || !tunnel.ws || tunnel.ws.readyState !== WebSocket.OPEN) {
          // Realm is offline or not found
          if (handshake.nextState === 1) {
            // Status Ping response
            clientSocket.write(createStatusResponsePacket(handshake.hostname || "unknown"));
          } else {
            // Login Disconnect response
            clientSocket.write(createDisconnectPacket(`Realm '${handshake.hostname}' is offline or does not exist.`));
          }
          setTimeout(() => clientSocket.destroy(), 500);
          return;
        }

        // Attach client socket to the resolved tunnel
        this.attachClientToTunnel(tunnel, clientSocket, handshakeBuffer);
      });

      clientSocket.on("error", () => {
        clientSocket.destroy();
      });
    });

    this.centralServer.listen(this.centralPort, "0.0.0.0", () => {
      console.log(`🌐 [SVL-Relay] Central Hostname/SNI Router active on port :${this.centralPort} (Unlimited Realms support)`);
    });

    this.centralServer.on("error", (err: any) => {
      console.warn(`⚠️ [SVL-Relay] Central port :${this.centralPort} unavailable (${err.message}). Falling back to dedicated port pool.`);
    });
  }

  /**
   * Resolves an ActiveTunnel by hostname (e.g. "SVL-FREE-7076-4DB4.realms.sunveil.net", "smp.realms.sunveil.net", or direct proxy host)
   */
  private findTunnelByHost(hostname: string): ActiveTunnel | undefined {
    if (!hostname) {
      if (this.activeTunnels.size > 0) {
        return this.activeTunnels.values().next().value;
      }
      return undefined;
    }

    const lowerHost = hostname.toLowerCase().trim();
    const subdomain = lowerHost.split(".")[0] || "";

    // 1. Direct case-insensitive match on serverKey or subdomain
    for (const [key, tunnel] of this.activeTunnels.entries()) {
      const lowerKey = key.toLowerCase();
      if (lowerKey === lowerHost || lowerKey === subdomain) {
        return tunnel;
      }
    }

    // 2. Normalized search without hyphens/underscores
    const cleanHost = lowerHost.replace(/[^a-z0-9]/gi, "");
    const cleanSubdomain = subdomain.replace(/[^a-z0-9]/gi, "");
    for (const [key, tunnel] of this.activeTunnels.entries()) {
      const cleanKey = key.toLowerCase().replace(/[^a-z0-9]/gi, "");
      if (cleanKey === cleanSubdomain || cleanHost.startsWith(cleanKey)) {
        return tunnel;
      }
    }

    // 3. Fallback for public domain, proxy host, localhost, or if only 1 tunnel is connected
    const directHost = (process.env.TUNNEL_PUBLIC_HOST || "").toLowerCase();
    const publicDomain = this.publicDomain.toLowerCase();

    if (
      lowerHost === directHost ||
      lowerHost === publicDomain ||
      lowerHost.endsWith(publicDomain) ||
      lowerHost.includes("proxy.rlwy.net") ||
      lowerHost === "localhost" ||
      lowerHost === "127.0.0.1" ||
      this.activeTunnels.size === 1
    ) {
      if (this.activeTunnels.size > 0) {
        return this.activeTunnels.values().next().value;
      }
    }

    return undefined;
  }

  /**
   * Checks if an IP is exceeding anti-bot / flood limits
   */
  private isIpRateLimited(rawIp: string): boolean {
    const ip = rawIp.replace(/^::ffff:/, "");
    if (ip === "127.0.0.1" || ip === "localhost") return false;

    const now = Date.now();
    const timestamps = (this.ipConnectionHistory.get(ip) || []).filter(t => now - t < RATE_WINDOW_MS);
    timestamps.push(now);
    this.ipConnectionHistory.set(ip, timestamps);

    return timestamps.length > MAX_CONN_PER_IP_WINDOW;
  }

  /**
   * Mounts the WebSocket server on an existing HTTP/Fastify instance
   */
  public attach(httpServer: any) {
    this.wss = new WebSocketServer({ noServer: true });

    httpServer.on("upgrade", (request: IncomingMessage, socket: any, head: Buffer) => {
      const url = new URL(request.url || "", `http://${request.headers.host || "localhost"}`);
      if (url.pathname === "/api/v1/tunnel/ws") {
        const token = url.searchParams.get("token") || 
          (request.headers.authorization?.startsWith("Bearer ") ? request.headers.authorization.substring(7) : "");
        const serverKey = url.searchParams.get("serverKey") || "";

        if (!isValidToken(token) || !serverKey) {
          socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
          socket.destroy();
          return;
        }

        this.wss?.handleUpgrade(request, socket, head, (ws) => {
          this.wss?.emit("connection", ws, request, serverKey);
        });
      }
    });

    this.wss.on("connection", (ws: WebSocket, request: IncomingMessage, serverKey: string) => {
      this.handleTunnelConnection(ws, serverKey);
    });

    console.log(`🛡️ Sunveil Secure Relay Tunnel initialized (SNI Router + Pool ${this.minPort}-${this.maxPort})`);
  }

  /**
   * Allocates an unused TCP port from the pool
   */
  private allocatePort(): number | null {
    for (let port = this.minPort; port <= this.maxPort; port++) {
      if (!this.portToTunnel.has(port)) {
        return port;
      }
    }
    return null;
  }

  /**
   * Attaches an incoming player socket to a tunnel
   */
  private attachClientToTunnel(tunnel: ActiveTunnel, clientSocket: net.Socket, initialPayload: Buffer) {
    if (tunnel.clientSockets.size >= MAX_CONCURRENT_CLIENTS_PER_TUNNEL) {
      clientSocket.destroy();
      return;
    }

    const connId = this.connectionCounter++;
    tunnel.clientSockets.set(connId, clientSocket);
    tunnel.activeClients = tunnel.clientSockets.size;

    // Send PKT_OPEN to Bridge
    const openFrame = Buffer.alloc(5);
    openFrame.writeUInt8(PKT_OPEN, 0);
    openFrame.writeUInt32BE(connId, 1);
    if (tunnel.ws.readyState === WebSocket.OPEN) {
      tunnel.ws.send(openFrame);
    }

    // Send initial handshake payload
    const header = Buffer.alloc(5);
    header.writeUInt8(PKT_DATA, 0);
    header.writeUInt32BE(connId, 1);
    tunnel.ws.send(Buffer.concat([header, initialPayload]));
    tunnel.bytesReceived += initialPayload.length;

    // Forward stream data
    clientSocket.on("data", (chunk: Buffer) => {
      if (tunnel.ws.readyState === WebSocket.OPEN) {
        const frameHeader = Buffer.alloc(5);
        frameHeader.writeUInt8(PKT_DATA, 0);
        frameHeader.writeUInt32BE(connId, 1);
        tunnel.ws.send(Buffer.concat([frameHeader, chunk]));
        tunnel.bytesReceived += chunk.length;
      }
    });

    clientSocket.on("close", () => {
      tunnel.clientSockets.delete(connId);
      tunnel.activeClients = tunnel.clientSockets.size;
      if (tunnel.ws.readyState === WebSocket.OPEN) {
        const closeFrame = Buffer.alloc(5);
        closeFrame.writeUInt8(PKT_CLOSE, 0);
        closeFrame.writeUInt32BE(connId, 1);
        tunnel.ws.send(closeFrame);
      }
    });

    clientSocket.on("error", () => {
      clientSocket.destroy();
    });
  }

  /**
   * Handles incoming WebSocket connection from a Minecraft server Bridge
   */
  private handleTunnelConnection(ws: WebSocket, serverKey: string) {
    this.closeTunnel(serverKey);

    const port = this.allocatePort() || 25600;
    const clientSockets = new Map<number, net.Socket>();

    // Dedicated fallback TCP Server for this specific server
    const tcpServer = net.createServer((clientSocket) => {
      const clientIp = clientSocket.remoteAddress || "unknown";

      if (this.isIpRateLimited(clientIp)) {
        clientSocket.destroy();
        return;
      }

      let isHandshakeVerified = false;
      let handshakeBuffer = Buffer.alloc(0);

      clientSocket.on("data", (chunk: Buffer) => {
        if (isHandshakeVerified) return;

        if (chunk.length > MAX_PACKET_SIZE) {
          clientSocket.destroy();
          return;
        }

        handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);
        const handshake = parseMinecraftHandshake(handshakeBuffer);

        if (!handshake) {
          if (handshakeBuffer.length > 1024) {
            clientSocket.destroy();
          }
          return;
        }

        isHandshakeVerified = true;
        this.attachClientToTunnel(tunnel, clientSocket, handshakeBuffer);
      });

      clientSocket.on("error", () => {
        clientSocket.destroy();
      });
    });

    tcpServer.listen(port, "0.0.0.0", () => {
      console.log(`🛡️ [SVL-Tunnel] Realm '${serverKey}' online: ${serverKey}.${this.publicDomain} (:25565) & Fallback :${port}`);
    });

    const vanityHost = `${serverKey}.${this.publicDomain}`;
    const directHost = vanityHost;
    const directPort = Number(process.env.TUNNEL_PUBLIC_PORT) || port;

    const tunnel: ActiveTunnel = {
      serverKey,
      assignedPort: directPort,
      publicHost: directHost,
      connectedAt: Date.now(),
      bytesReceived: 0,
      bytesSent: 0,
      activeClients: 0,
      tcpServer,
      ws,
      clientSockets
    };

    this.activeTunnels.set(serverKey, tunnel);
    this.portToTunnel.set(port, serverKey);
    if (directPort !== port) {
      this.portToTunnel.set(directPort, serverKey);
    }

    // Send Tunnel Registration Confirmation to Bridge
    const welcomeMsg = JSON.stringify({
      type: "TUNNEL_READY",
      serverKey,
      publicHost: directHost,
      publicPort: directPort,
      fallbackPort: port,
      timestamp: Date.now()
    });
    ws.send(welcomeMsg);

    // Handle incoming frames from Bridge
    ws.on("message", (data: Buffer | string) => {
      if (typeof data === "string") {
        try {
          const parsed = JSON.parse(data);
          if (parsed.type === "PING") {
            ws.send(JSON.stringify({ type: "PONG", timestamp: Date.now() }));
          }
        } catch {}
        return;
      }

      if (!Buffer.isBuffer(data) || data.length < 5) return;

      const pktType = data.readUInt8(0);
      const connId = data.readUInt32BE(1);
      const targetSocket = clientSockets.get(connId);

      if (pktType === PKT_DATA && targetSocket && !targetSocket.destroyed) {
        const payload = data.subarray(5);
        targetSocket.write(payload);
        tunnel.bytesSent += payload.length;
      } else if (pktType === PKT_CLOSE && targetSocket) {
        targetSocket.destroy();
        clientSockets.delete(connId);
        tunnel.activeClients = clientSockets.size;
      }
    });

    // Keepalive Ping every 20 seconds to prevent Cloudflare/Railway idle timeout (100-120s)
    const pingTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.ping();
      } else {
        clearInterval(pingTimer);
      }
    }, 20000);

    ws.on("close", () => {
      clearInterval(pingTimer);
      console.log(`🛡️ [SVL-Tunnel] Bridge disconnected for '${serverKey}'.`);
      this.closeTunnel(serverKey);
    });

    ws.on("error", (err) => {
      clearInterval(pingTimer);
      console.error(`🛡️ [SVL-Tunnel] WebSocket error on '${serverKey}':`, err.message);
      this.closeTunnel(serverKey);
    });
  }

  /**
   * Closes a tunnel and frees all resources
   */
  public closeTunnel(serverKey: string) {
    const tunnel = this.activeTunnels.get(serverKey);
    if (!tunnel) return;

    for (const socket of tunnel.clientSockets.values()) {
      try { socket.destroy(); } catch {}
    }
    tunnel.clientSockets.clear();

    if (tunnel.tcpServer) {
      try {
        tunnel.tcpServer.close();
      } catch {}
    }

    this.portToTunnel.delete(tunnel.assignedPort);
    this.activeTunnels.delete(serverKey);
  }

  /**
   * Returns active tunnel info for a given serverKey
   */
  public getTunnel(serverKey: string) {
    return this.activeTunnels.get(serverKey);
  }

  /**
   * Returns all active tunnels
   */
  public getAllTunnels() {
    return Array.from(this.activeTunnels.values()).map(t => ({
      serverKey: t.serverKey,
      assignedPort: t.assignedPort,
      publicHost: t.publicHost,
      connectedAt: t.connectedAt,
      bytesReceived: t.bytesReceived,
      bytesSent: t.bytesSent,
      activeClients: t.activeClients
    }));
  }
}

export const relayServer = new RelayServer();
