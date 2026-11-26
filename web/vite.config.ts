import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Python Forge serves exactly index.html, assets/app.js and assets/app.css from re_harness/forge_web.
// Fixed names, one chunk and one stylesheet keep the build reproducible and the server's file list closed.
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "../re_harness/forge_web",
    emptyOutDir: true,
    cssCodeSplit: false,
    sourcemap: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/app.js",
        chunkFileNames: "assets/app.js",
        assetFileNames: (asset) =>
          asset.names.some((name) => name.endsWith(".css")) ? "assets/app.css" : "assets/[name][extname]",
        inlineDynamicImports: true,
      },
    },
  },
});
