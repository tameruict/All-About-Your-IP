import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri v2 expects a fixed dev port and no screen clearing so the Rust side
// can attach its own logs. See https://v2.tauri.app/start/frontend/vite/
const host = process.env.TAURI_DEV_HOST;

export default defineConfig(async () => ({
  plugins: [react()],

  // Tauri assets are served from the custom protocol in production,
  // so relative base keeps the bundle portable.
  base: "./",
  clearScreen: false,

  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // Rust sources are watched by the Tauri CLI, not by Vite.
      ignored: ["**/src-tauri/**"],
    },
  },

  envPrefix: ["VITE_", "TAURI_ENV_*"],

  build: {
    // Windows WebView2 is evergreen, and tokens.css relies on `color-mix()`
    // (Chromium 111+). Promising chrome105 made those declarations
    // guaranteed-invalid on the runtimes we actually support, so the floor is
    // now the real one.
    target: "chrome111",
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    minify: "esbuild",
    chunkSizeWarningLimit: 1500,
  },
}));
