import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath, URL } from "node:url";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    manifest: true,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:18990",
      "/admin": "http://127.0.0.1:18990",
      "/setup": "http://127.0.0.1:18990",
      "/config": "http://127.0.0.1:18990",
      "/hero.webp": "http://127.0.0.1:18990",
    },
  },
});
