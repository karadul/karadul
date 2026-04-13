# Stage 1: Build Web UI
FROM node:22-alpine AS web-builder

WORKDIR /build/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --legacy-peer-deps
COPY web/ ./
RUN npm run build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Copy web build output into the embedded directory
COPY --from=web-builder /build/web/dist ./internal/web/dist/

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o karadul ./cmd/karadul

# Stage 3: Runtime
FROM alpine:latest

RUN apk add --no-cache ca-certificates iptables ip6tables

COPY --from=go-builder /build/karadul /usr/local/bin/karadul

# Create data directory
RUN mkdir -p /var/lib/karadul

# Expose default ports
EXPOSE 8080/tcp
EXPOSE 3478/udp
EXPOSE 51820/udp

VOLUME ["/var/lib/karadul"]

ENTRYPOINT ["karadul"]
CMD ["server", "--addr=:8080"]
