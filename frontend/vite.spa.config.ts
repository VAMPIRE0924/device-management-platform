import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const rootDir = fileURLToPath(new URL(".", import.meta.url));
const apiTarget = process.env.I5CLOUD_DEV_API_TARGET ?? "http://127.0.0.1:8088";

// The single formal frontend build. Its static output is embedded into the Go
// server and is also used by local development and contract tests.
export default defineConfig({
  root: fileURLToPath(new URL("./spa", import.meta.url)),
  publicDir: fileURLToPath(new URL("./public", import.meta.url)),
  plugins: [react()],
  server: {
    proxy: {
      "/api": { target: apiTarget, changeOrigin: true },
      "/access": { target: apiTarget, changeOrigin: true, ws: true },
      "/health": { target: apiTarget, changeOrigin: true },
    },
  },
  build: {
    outDir: `${rootDir}dist-spa`,
    emptyOutDir: true,
    // Production bundles may contain sensitive implementation details in maps.
    sourcemap: false,
    rollupOptions: {
      input: {
        app: fileURLToPath(new URL("./spa/index.html", import.meta.url)),
        webssh: fileURLToPath(new URL("./spa/src/webssh.ts", import.meta.url)),
      },
      output: {
        entryFileNames: (chunk) => chunk.name === "webssh" ? "assets/webssh.js" : "assets/[name]-[hash].js",
      },
    },
  },
});
