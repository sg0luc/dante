import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Em desenvolvimento local (npm run dev), /api é repassado ao backend em :8000.
// Em produção, o Nginx do contêiner faz esse proxy (ver nginx.conf).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
  },
});

