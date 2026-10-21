FROM gradle:9.8.0-jdk21-noble@sha256:0076fefe482103cf751a047aae94ba3b1db84e3893865125ecf8f14b6a02ec60 AS build
WORKDIR /app
COPY internal/test/integration/components/java_grpc_tls/build.gradle.kts internal/test/integration/components/java_grpc_tls/settings.gradle.kts ./
COPY internal/test/integration/components/java_grpc_tls/src src
RUN gradle installDist --no-daemon
FROM eclipse-temurin:21-jre@sha256:227118764cccd3c3294617061aaa93a08309c63a395eefa83e6b35032992ea99
COPY --from=build /app/build/install/java-grpc-tls /app
ENTRYPOINT ["/app/bin/java-grpc-tls"]
