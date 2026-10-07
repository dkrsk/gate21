# syntax=docker/dockerfile:1

FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY src ./src
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-buildid=" -o /out/gate21 ./src/app/cmd/server

FROM alpine:3.21
RUN adduser -D -H -u 10001 gate21
USER gate21
WORKDIR /app
COPY --from=build /out/gate21 /app/gate21
COPY clients.json.example /app/clients.json
EXPOSE 8080
ENV AUTH_LISTEN_ADDR=:8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O- http://127.0.0.1:8080/healthz >/dev/null || exit 1
ENTRYPOINT ["/app/gate21"]
