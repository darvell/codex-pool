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
    // Never inline fonts as data: URIs. The app is served under
    // `font-src 'self'`, which blocks them, and small subsets (the ~1.3kB
    // Cyrillic ones) would otherwise be inlined and fail to load.
    assetsInlineLimit: (filePath) => (/\.(woff2?|ttf|otf|eot)$/.test(filePath) ? false : undefined),
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
