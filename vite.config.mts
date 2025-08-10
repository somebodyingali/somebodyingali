import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/somebodyingali/',   // ชื่อ repo ของคุณ
})
