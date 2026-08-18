/*
 * Copyright (c) 2026 Sunveil Network. All rights reserved.
 * PROPRIETARY & CONFIDENTIAL — See LICENSE for terms.
 *
 * Production build configuration: bundles, minifies, and strips all
 * comments from the server source to harden against reverse-engineering.
 */

import { build } from "esbuild";

const BANNER = `/*! Copyright (c) 2026 Sunveil Network. All rights reserved. PROPRIETARY & CONFIDENTIAL. */`;

await build({
  entryPoints: ["src/server.ts"],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outfile: "dist/server.min.mjs",
  minify: true,
  treeShaking: true,
  legalComments: "none",
  banner: { js: BANNER },
  external: [
    // Node builtins
    "node:*",
    // npm dependencies (resolved at runtime from node_modules)
    "@fastify/*",
    "fastify",
    "dotenv",
    "pino",
    "pino-pretty",
  ],
  define: {
    "process.env.NODE_ENV": '"production"',
  },
});

console.log("✓ Production build → dist/server.min.mjs (minified, comments stripped)");
