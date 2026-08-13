FROM golang:1.26.5@sha256:0f70d7d828acd8456022127f31975364e58d792999a7e92af6fc972e124bb6b0 AS fault-builder

WORKDIR /build
COPY java/fault/Makefile java/fault/getsockopt_fault_shim.c java/fault/getsockopt_fault_shim.h java/fault/getsockopt_fault_shim_test.c ./
RUN make test
COPY java/pidreuse/pid_reuse_supervisor.c java/pidreuse/pid_reuse_supervisor_test.c ./
RUN cc -std=c11 -Wall -Wextra -Werror -O2 -static \
      -o pid-reuse-supervisor-test pid_reuse_supervisor_test.c && \
    ./pid-reuse-supervisor-test && \
    cc -std=c11 -Wall -Wextra -Werror -O2 -static \
      -o pid-reuse-supervisor pid_reuse_supervisor.c

FROM maven:3.9.12-eclipse-temurin-21@sha256:c3c9d3ac4ce8431a3995c0318b8d390f448e693dd4fabc16e9b68d2e1f3d7b46 AS builder

WORKDIR /build
COPY java/pom.xml ./pom.xml
RUN --mount=type=cache,target=/root/.m2 mvn --batch-mode --no-transfer-progress dependency:resolve
COPY java/src/ ./src/
RUN --mount=type=cache,target=/root/.m2 mvn --batch-mode --no-transfer-progress package

FROM eclipse-temurin:21.0.10_7-jre@sha256:34a58218d838035428163eb35abb629944c5906d1bedcfef8bc8864cce11dfe5

WORKDIR /app
COPY --from=builder /build/target/apache-java-https-backend.jar /app/backend.jar
COPY .runtime/artifacts/official-javaagent.jar /otel/official-javaagent.jar
COPY .runtime/artifacts/obi-otel-extension.jar /otel/obi-otel-extension.jar
COPY --from=fault-builder /build/libobi-java-remote-parent-fault.so /otel/libobi-java-remote-parent-fault.so
COPY --from=fault-builder /build/pid-reuse-supervisor /otel/pid-reuse-supervisor
RUN install -d -m 0700 /run/obi-demo/fault

ENTRYPOINT ["java", "-jar", "/app/backend.jar"]
