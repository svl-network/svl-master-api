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
  tcpServer: net.Server;
  ws: WebSocket;
  clientSockets: Map<number, net.Socket>;
}

// Packet Types for Multiplexed Tunnel
const PKT_OPEN = 0x01;
const PKT_DATA = 0x02;
const PKT_CLOSE = 0x03;
const PKT_PING = 0x04;
const PKT_PONG = 0x05;

// Security Limits & Anti-Abuse
const MAX_PACKET_SIZE = 2 * 1024 * 1024; // 2 MB max packet size
const MAX_CONCURRENT_CLIENTS_PER_TUNNEL = 60;
const MAX_CONN_PER_IP_WINDOW = 25; // Max 25 connection handshakes per minute per IP
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
 * Strict Minecraft Protocol Handshake Validator
 * Ensures only legitimate Minecraft Java Edition game traffic is forwarded through the tunnel.
 * Blocks HTTP, SSH, Telnet, SOCKS proxies, Port Scans, Malware C2, and Raw Exploits.
 */
function isValidMinecraftHandshake(buffer: Buffer): boolean {
  if (!buffer || buffer.length < 2) return false;

  // Legacy Minecraft Ping format (1.6 and below): 0xFE (Legacy Server List Ping)
  if (buffer[0] === 0xFE) return true;

  // Modern Minecraft Handshake packet:
  // [VarInt: length][VarInt: packetID (0x00)][VarInt: protocolVersion][VarInt: stringLength][utf8 string: address][unsigned short: port][VarInt: nextState (1 or 2)]
  let offset = 0;
  const pktLen = readVarInt(buffer, offset);
  if (!pktLen || pktLen.value <= 0 || pktLen.value > 1024) return false;
  offset += pktLen.bytesRead;

  const pktId = readVarInt(buffer, offset);
  if (!pktId || pktId.value !== 0x00) return false; // Handshake packet ID MUST be 0x00
  offset += pktId.bytesRead;

  const protocolVersion = readVarInt(buffer, offset);
  if (!protocolVersion) return false;
  offset += protocolVersion.bytesRead;

  const hostLength = readVarInt(buffer, offset);
  if (!hostLength || hostLength.value < 0 || hostLength.value > 255) return false;
  offset += hostLength.bytesRead;

  if (buffer.length < offset + hostLength.value + 2) return false;
  offset += hostLength.value + 2; // Host string + 2 bytes unsigned short port

  const nextState = readVarInt(buffer, offset);
  if (!nextState || (nextState.value !== 1 && nextState.value !== 2)) return false; // 1 = Status/Ping, 2 = Login

  return true;
}

export class RelayServer {
  private wss: WebSocketServer | null = null;
  private activeTunnels = new Map<string, ActiveTunnel>(); // serverKey -> ActiveTunnel
  private portToTunnel = new Map<number, string>(); // port -> serverKey
  private minPort = Number(process.env.TUNNEL_PORT_MIN) || 25600;
  private maxPort = Number(process.env.TUNNEL_PORT_MAX) || 25700;
  private publicHost = process.env.TUNNEL_PUBLIC_HOST || "realms.sunveil.net";
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

    console.log(`🛡️ Sunveil Secure Relay Tunnel initialized (Port pool: ${this.minPort}-${this.maxPort})`);
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
   * Handles incoming WebSocket connection from a Minecraft server Bridge
   */
  private handleTunnelConnection(ws: WebSocket, serverKey: string) {
    // Clean up any previous tunnel for this serverKey
    this.closeTunnel(serverKey);

    const port = this.allocatePort();
    if (!port) {
      ws.close(1013, "No available tunnel ports in pool");
      return;
    }

    const clientSockets = new Map<number, net.Socket>();

    const tcpServer = net.createServer((clientSocket) => {
      const clientIp = clientSocket.remoteAddress || "unknown";

      // 1. Anti-Botting & Flood Protection Check
      if (this.isIpRateLimited(clientIp)) {
        console.warn(`🛡️ [SVL-Tunnel] Dropped flood/botting connection from ${clientIp} on '${serverKey}'`);
        clientSocket.destroy();
        return;
      }

      const tunnel = this.activeTunnels.get(serverKey);
      if (!tunnel || clientSockets.size >= MAX_CONCURRENT_CLIENTS_PER_TUNNEL) {
        clientSocket.destroy();
        return;
      }

      const connId = this.connectionCounter++;
      clientSockets.set(connId, clientSocket);
      tunnel.activeClients = clientSockets.size;

      let isHandshakeVerified = false;
      let handshakeBuffer = Buffer.alloc(0);

      // 2. Client Traffic Inspection & Forwarding
      clientSocket.on("data", (chunk: Buffer) => {
        // Enforce max packet size limit
        if (chunk.length > MAX_PACKET_SIZE) {
          console.warn(`🛡️ [SVL-Tunnel] Oversized packet from ${clientIp} on '${serverKey}'. Terminating.`);
          clientSocket.destroy();
          return;
        }

        // 3. Strict Minecraft Protocol Inspection on Initial Handshake
        if (!isHandshakeVerified) {
          handshakeBuffer = Buffer.concat([handshakeBuffer, chunk]);

          // Verify if the initial payload is a valid Minecraft Handshake
          if (!isValidMinecraftHandshake(handshakeBuffer)) {
            // Give up to 1024 bytes to form the handshake; if invalid, reject non-Minecraft traffic immediately
            if (handshakeBuffer.length > 1024 || (handshakeBuffer.length >= 3 && handshakeBuffer[0] !== 0xFE && handshakeBuffer[1] !== 0x00)) {
              console.warn(`🛡️ [SVL-Tunnel] Blocked NON-MINECRAFT payload (Malware/Proxy/Scan) from ${clientIp} on '${serverKey}'`);
              clientSocket.destroy();
              return;
            }
            return; // Wait for full handshake frame
          }

          isHandshakeVerified = true;

          // Open frame to Bridge once verified as legitimate Minecraft connection
          const openFrame = Buffer.alloc(5);
          openFrame.writeUInt8(PKT_OPEN, 0);
          openFrame.writeUInt32BE(connId, 1);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(openFrame);
          }

          // Forward verified handshake payload
          const header = Buffer.alloc(5);
          header.writeUInt8(PKT_DATA, 0);
          header.writeUInt32BE(connId, 1);
          ws.send(Buffer.concat([header, handshakeBuffer]));
          tunnel.bytesReceived += handshakeBuffer.length;
          return;
        }

        // Forward subsequent Minecraft stream data
        if (ws.readyState === WebSocket.OPEN) {
          const header = Buffer.alloc(5);
          header.writeUInt8(PKT_DATA, 0);
          header.writeUInt32BE(connId, 1);
          ws.send(Buffer.concat([header, chunk]));
          tunnel.bytesReceived += chunk.length;
        }
      });

      clientSocket.on("close", () => {
        clientSockets.delete(connId);
        if (tunnel) tunnel.activeClients = clientSockets.size;
        if (isHandshakeVerified && ws.readyState === WebSocket.OPEN) {
          const closeFrame = Buffer.alloc(5);
          closeFrame.writeUInt8(PKT_CLOSE, 0);
          closeFrame.writeUInt32BE(connId, 1);
          ws.send(closeFrame);
        }
      });

      clientSocket.on("error", () => {
        clientSocket.destroy();
      });
    });

    tcpServer.listen(port, "0.0.0.0", () => {
      console.log(`🛡️ [SVL-Tunnel] Server '${serverKey}' protected & bound to public relay port :${port}`);
    });

    const tunnel: ActiveTunnel = {
      serverKey,
      assignedPort: port,
      publicHost: this.publicHost,
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

    // Send Tunnel Registration Confirmation to Bridge
    const welcomeMsg = JSON.stringify({
      type: "TUNNEL_READY",
      serverKey,
      publicHost: this.publicHost,
      publicPort: port,
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

    ws.on("close", () => {
      console.log(`🛡️ [SVL-Tunnel] Bridge disconnected for '${serverKey}'. Freeing port :${port}`);
      this.closeTunnel(serverKey);
    });

    ws.on("error", (err) => {
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

    try {
      tunnel.tcpServer.close();
    } catch {}

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
