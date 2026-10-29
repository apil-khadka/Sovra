# syntax=docker/dockerfile:1

# SOV-041 packaged origin: the React production bundle is built
# here and copied into the backend jar, so every app instance
# serves the SPA, BFF, and API from one origin. No Node toolchain
# survives into the runtime image. Build context is the repository
# root (see compose.yaml); .dockerignore keeps secrets, local
# research, and build outputs out of the context.
FROM node:24-alpine AS frontend-build
WORKDIR /frontend
COPY frontend/package.json frontend/pnpm-lock.yaml ./
RUN npm install -g pnpm@10 && pnpm install --frozen-lockfile
COPY frontend/ ./
RUN pnpm run build

# Pinned to the newest published container patch; 25.0.5 images were not on
# Docker Hub on 2026-10-27. Bump to 25.0.5_8 tags when they appear.
FROM eclipse-temurin:25.0.4.1_1-jdk AS build
WORKDIR /app
COPY backend/.mvn .mvn
COPY backend/mvnw backend/pom.xml ./
# Cache-warm with the lifecycle itself, not dependency:go-offline: the
# go-offline goal resolves excluded artifacts (SOV-036 excludes walt-id's
# unresolvable mdoc snapshot), while compile honors exclusions.
RUN ./mvnw -q -DskipTests test-compile
COPY backend/src src
COPY --from=frontend-build /frontend/dist src/main/resources/static
RUN ./mvnw -q -DskipTests package
# Exploded layout (SOV-017): Boot 4 ships no layertools jarmode, so
# unpack with the JDK jar tool. The same image then boots either the
# API (default entrypoint) or the isolated quarantine worker
# (dev.sovra.worker.QuarantineWorkerMain), a plain main class that a
# nested-jar launch cannot address.
RUN mkdir -p /exploded && cd /exploded && jar -xf /app/target/sovra-backend-*.jar

FROM eclipse-temurin:25.0.4.1_1-jre-alpine
RUN addgroup -S sovra && adduser -S sovra -G sovra
USER sovra
WORKDIR /app
COPY --from=build --chown=sovra:sovra /exploded/ /app/
EXPOSE 8080
ENTRYPOINT ["java", "-cp", "BOOT-INF/classes:BOOT-INF/lib/*", "dev.sovra.SovraApplication"]
