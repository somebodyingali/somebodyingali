import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  base: '/somebodyingali/', // ต้องตรงกับชื่อ repo และมี / หน้า-หลัง
})
