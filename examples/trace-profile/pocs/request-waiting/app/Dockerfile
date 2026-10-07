FROM golang:1.27.0@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS builder
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /out/obi-poc-waiting .
FROM scratch
COPY --from=builder /out/obi-poc-waiting /obi-poc-waiting
USER 65532:65532
ENTRYPOINT ["/obi-poc-waiting"]
