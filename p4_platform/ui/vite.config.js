import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // '..' is p4_platform; '../..' is the repo root so sibling modules
    // (p1_domain/ui, p2_logs/ui, ...) can be read by import.meta.glob.
    fs: { allow: ['..', '../..'] },
  },
})
