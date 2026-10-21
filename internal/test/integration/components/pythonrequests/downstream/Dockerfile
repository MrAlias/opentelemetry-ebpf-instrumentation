FROM golang:1.27.0@sha256:0ecdc2a9f6156af6451080bfe3d8382a662fcc4e209608c6f919e643453514c1 AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/test/integration/components/pythonrequests/downstream/main.go ./main.go
RUN CGO_ENABLED=0 go build -o /downstream main.go
FROM scratch
COPY --from=builder /downstream /downstream
ENTRYPOINT ["/downstream"]
