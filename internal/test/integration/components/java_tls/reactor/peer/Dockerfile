FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/java_tls/reactor/peer/ peer/
RUN CGO_ENABLED=0 go build -o /peer ./peer

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11
COPY --from=build /peer /peer
ENTRYPOINT ["/peer"]
