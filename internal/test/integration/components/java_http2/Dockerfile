FROM gradle:9.8.0-jdk21-noble@sha256:0076fefe482103cf751a047aae94ba3b1db84e3893865125ecf8f14b6a02ec60 AS source
WORKDIR /app
COPY internal/test/integration/components/java_http2/Source.java .
RUN javac --release 11 Source.java
CMD ["java", "Source"]

FROM golang:1.27.2@sha256:007a316059246276cb214df93950be77837545dc78007a73e0291a4963d5d3bf AS backend-build
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/java_http2/backend.go ./backend.go
RUN CGO_ENABLED=0 go build -o /backend backend.go

FROM scratch AS backend
COPY --from=backend-build /backend /backend
ENTRYPOINT ["/backend"]
