import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Local backend from compose (app-a) or ./mvnw spring-boot:run.
      // /api covers data calls and the BFF session surface; /oauth2
      // and /login carry the Keycloak login chain, whose registered
      // callback and landing stay on the backend origin (see the
      // SOV-041 holder/browser assessment for the demo loop).
      '/api': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/login': 'http://localhost:8080',
    },
  },
})
