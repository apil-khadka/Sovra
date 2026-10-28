# syntax=docker/dockerfile:1

# Pinned to the newest published container patch; 25.0.5 images were not on
# Docker Hub on 2026-10-27. Bump to 25.0.5_8 tags when they appear.
FROM eclipse-temurin:25.0.4.1_1-jdk AS build
WORKDIR /app
COPY .mvn .mvn
COPY mvnw pom.xml ./
# Cache-warm with the lifecycle itself, not dependency:go-offline: the
# go-offline goal resolves excluded artifacts (SOV-036 excludes walt-id's
# unresolvable mdoc snapshot), while compile honors exclusions.
RUN ./mvnw -q -DskipTests test-compile
COPY src src
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
