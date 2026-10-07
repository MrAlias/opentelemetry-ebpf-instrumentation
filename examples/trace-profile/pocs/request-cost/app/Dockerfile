FROM --platform=$BUILDPLATFORM golang:1.27.1@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o /out/obi-poc-cost .

FROM scratch
COPY --from=builder /out/obi-poc-cost /obi-poc-cost
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/obi-poc-cost"]
