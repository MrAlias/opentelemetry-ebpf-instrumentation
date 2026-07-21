FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS builder

WORKDIR /build
COPY java/pom.xml ./pom.xml
RUN --mount=type=cache,target=/root/.m2 mvn --batch-mode --no-transfer-progress dependency:go-offline
COPY java/src/ ./src/
RUN --mount=type=cache,target=/root/.m2 mvn --batch-mode --no-transfer-progress package

FROM eclipse-temurin:21.0.10_7-jre@sha256:34a58218d838035428163eb35abb629944c5906d1bedcfef8bc8864cce11dfe5

WORKDIR /app
COPY --from=builder /build/target/apache-java-https-backend.jar /app/backend.jar
COPY .runtime/artifacts/official-javaagent.jar /otel/official-javaagent.jar
COPY .runtime/artifacts/obi-otel-extension.jar /otel/obi-otel-extension.jar

ENTRYPOINT ["java", "-jar", "/app/backend.jar"]
