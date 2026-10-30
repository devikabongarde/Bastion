import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const contentSecurityPolicy =
  "default-src 'self'; connect-src 'self'; img-src 'self' data:; " +
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; " +
  "script-src 'self'; object-src 'none'; " +
  "base-uri 'self'; frame-ancestors 'none'";

const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env;
const apiTarget = env?.BG_API_URL ?? "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    strictPort: true,
    proxy: { "/api": apiTarget, "/health": apiTarget },
    headers: {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  },
  preview: {
    host: "127.0.0.1",
    strictPort: true,
    headers: {
      "Content-Security-Policy": contentSecurityPolicy,
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  },
});
