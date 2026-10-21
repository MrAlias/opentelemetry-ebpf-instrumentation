FROM golang:1.27.2@sha256:820153096fda4de6ac1b7194d12e416b7dd8f4e9a33d17e0345b111b945162d8 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal/test/integration/components/java_grpc_tls/receiver/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /receiver main.go
FROM alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0
COPY --from=build /receiver /receiver
ENTRYPOINT ["/receiver"]
