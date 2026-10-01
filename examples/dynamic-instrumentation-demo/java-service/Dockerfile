FROM eclipse-temurin:21@sha256:efd34b940f2d5a621605c8531c2afb7759c936b6c2ef637a69aa3bf3e1e789d1 AS builder

WORKDIR /src
COPY src/ src/
RUN javac -d out src/demo/inventory/*.java

FROM ghcr.io/open-telemetry/opentelemetry-operator/autoinstrumentation-java:2.20.0@sha256:5671df6bb256d3659c11b4cfce00009c60b1206d2d46eb3c576742a3f5676900 AS opentelemetry

FROM eclipse-temurin:21-jre@sha256:8ec353b20d3aab0758572236b81b967c7077c40c4d0819ce97f9a1329d684603

WORKDIR /app
COPY --from=builder /src/out/ /app/
COPY --from=opentelemetry /javaagent.jar /opt/opentelemetry/javaagent.jar
EXPOSE 18082
ENTRYPOINT ["java", "-javaagent:/opt/opentelemetry/javaagent.jar", "-cp", "/app", "demo.inventory.InventoryServer"]
