# Pulp-ext-gin

Gin-based HTTP transport extension for Pulp. Registers four capabilities covering inbound HTTP, outbound fetch, WebSocket, and SSE. All four share a single Gin engine.

From [BananaLabs OSS](https://github.com/BananaLabs-OSS).

## Deployment

```go
import _ "github.com/BananaLabs-OSS/Pulp-ext-gin"
```

## Capabilities

- `transport.http.inbound`
- `transport.http.outbound`
- `transport.ws.inbound`
- `transport.sse`

## Environment

- `HTTP_PORT` — listen port (default 8080)
- `HTTP_CERT` — TLS cert PEM path (optional)
- `HTTP_KEY` — TLS key PEM path (optional)
- `HTTP_FETCH_ALLOW` — comma-separated host[:port] or CIDR entries that bypass the SSRF egress guard (optional; default seeds bananagine and minecraft-resolver by name)
