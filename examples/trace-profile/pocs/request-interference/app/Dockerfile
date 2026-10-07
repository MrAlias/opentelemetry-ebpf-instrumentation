FROM --platform=$BUILDPLATFORM golang:1.27.0@sha256:4013ae0f9e7994f8535c58c811f8f863fbed38b72e0d51e6592156f758d66146 AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/obi-poc-interference .

FROM scratch
COPY --from=builder /out/obi-poc-interference /obi-poc-interference
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/obi-poc-interference"]
