FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/dotnet-httpclient/peer/ ./peer/
RUN CGO_ENABLED=0 go build -o /peer ./peer

FROM scratch
COPY --from=builder /peer /peer
ENTRYPOINT ["/peer"]
