FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /tcpblaster .

FROM alpine:3.19
COPY --from=builder /tcpblaster /usr/local/bin/tcpblaster
ENTRYPOINT ["tcpblaster"]
