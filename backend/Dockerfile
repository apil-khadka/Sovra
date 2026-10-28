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

FROM eclipse-temurin:25.0.4.1_1-jre-alpine
RUN addgroup -S sovra && adduser -S sovra -G sovra
USER sovra
WORKDIR /app
COPY --from=build --chown=sovra:sovra /app/target/sovra-backend-*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
