FROM golang:1.26.5@sha256:0f70d7d828acd8456022127f31975364e58d792999a7e92af6fc972e124bb6b0 AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY examples/apache-java-https/tracecheck/ examples/apache-java-https/tracecheck/
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/trace-receiver \
    ./examples/apache-java-https/tracecheck/cmd/receiver
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/trace-scenario \
    ./examples/apache-java-https/tracecheck/cmd/scenario
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/trace-benchmark \
    ./examples/apache-java-https/tracecheck/cmd/benchmark
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/map-pressure \
    ./examples/apache-java-https/tracecheck/cmd/mappressure
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/map-state \
    ./examples/apache-java-https/tracecheck/cmd/mapstate
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/generation-fault \
    ./examples/apache-java-https/tracecheck/cmd/generationfault
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/fault-bridge \
    ./examples/apache-java-https/tracecheck/cmd/faultbridge
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/security-probe \
    ./examples/apache-java-https/tracecheck/cmd/securityprobe
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/coalesced-source \
    ./examples/apache-java-https/tracecheck/cmd/coalescedsource

FROM scratch
COPY --from=builder /out/trace-receiver /trace-receiver
COPY --from=builder /out/trace-scenario /trace-scenario
COPY --from=builder /out/trace-benchmark /trace-benchmark
COPY --from=builder /out/map-pressure /map-pressure
COPY --from=builder /out/map-state /map-state
COPY --from=builder /out/generation-fault /generation-fault
COPY --from=builder /out/fault-bridge /fault-bridge
COPY --from=builder /out/security-probe /security-probe
COPY --from=builder /out/coalesced-source /coalesced-source
ENTRYPOINT ["/trace-receiver"]
