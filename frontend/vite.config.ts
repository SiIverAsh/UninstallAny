import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const srcDir = decodeURIComponent(new URL("./src", import.meta.url).pathname).replace(
  /^\/([A-Za-z]:)/,
  "$1",
);

// Tauri v2 compatible Vite config: strict port 1420 for tauri dev, relative assets for bundle.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": srcDir,
    },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/crates/**", "**/target/**"],
    },
  },
});
