import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Local backend from compose (app-a) or ./mvnw spring-boot:run.
      // /api covers data calls and the BFF session surface; /oauth2
      // and /login carry the Keycloak login chain. This proxy is for
      // local frontend iteration only: the packaged demo serves the
      // built SPA from the backend origin itself (SOV-041), so the
      // login loop never leaves http://localhost:8080.
      '/api': 'http://localhost:8080',
      '/oauth2': 'http://localhost:8080',
      '/login': 'http://localhost:8080',
    },
  },
})
