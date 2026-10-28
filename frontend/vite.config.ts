import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Local backend from compose (app-a) or ./mvnw spring-boot:run.
      '/api': 'http://localhost:8080',
    },
  },
})
