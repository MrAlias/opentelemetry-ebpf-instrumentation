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
    CGO_ENABLED=0 go build -trimpath -o /out/map-pressure \
    ./examples/apache-java-https/tracecheck/cmd/mappressure
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -o /out/fault-bridge \
    ./examples/apache-java-https/tracecheck/cmd/faultbridge

FROM scratch
COPY --from=builder /out/trace-receiver /trace-receiver
COPY --from=builder /out/trace-scenario /trace-scenario
COPY --from=builder /out/map-pressure /map-pressure
COPY --from=builder /out/fault-bridge /fault-bridge
ENTRYPOINT ["/trace-receiver"]
