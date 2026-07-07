# HTTP2

http2 is an implementation of HTTP/2 protocol for [fasthttp](https://github.com/valyala/fasthttp).

Fork from [github.com/dgrr/http2](https://github.com/dgrr/http2)

## Download

```bash
go get github.com/lafriks/http2@latest
```

## Help

If you need any help to set up, contributing or understanding this repo, you can contact me on [gofiber's Discord](https://gofiber.io/discord).

## How to use the server?

The usual way in is TLS with ALPN negotiation: call
[ConfigureServer](https://pkg.go.dev/github.com/lafriks/http2#ConfigureServer)
and serve with TLS. (For cleartext HTTP/2 see [h2c](#h2c-cleartext-http2)
below.)

```go
package main

import (
	"github.com/valyala/fasthttp"
	"github.com/lafriks/http2"
)

func main() {
    s := &fasthttp.Server{
        Handler: yourHandler,
        Name:    "HTTP2 test",
    }

    http2.ConfigureServer(s, http2.ServerConfig{})
    
    s.ListenAndServeTLS(...)
}
```

### Graceful shutdown

[ConfigureServer](https://pkg.go.dev/github.com/lafriks/http2#ConfigureServer) returns an
`*http2.Server` whose `Shutdown` drains the HTTP/2 connections following the
RFC 9113 GOAWAY sequence: in-flight and just-created streams are still served,
new streams are refused with a retry-safe error. Call it before shutting down
the fasthttp server, which otherwise waits for the HTTP/2 connections without
being able to close them:

```go
h2s := http2.ConfigureServer(s, http2.ServerConfig{})

// ... on shutdown signal:
h2s.Shutdown(ctx) // drain the HTTP/2 connections
s.Shutdown()      // then stop the fasthttp server
```

See [examples/simple](./examples/simple/main.go) for a complete example.

### h2c (cleartext HTTP/2)

`ConfigureServer` only wires HTTP/2 into fasthttp's TLS+ALPN negotiation,
and the HTTP/1.1 Upgrade mechanism (`Upgrade: h2c`) is not supported.

Prior-knowledge h2c works, though: clients that speak HTTP/2 directly over
a plain TCP connection — gRPC clients with insecure credentials, or
`curl --http2-prior-knowledge` — can be served by owning the accept loop
and handing every connection to
[ServeConn](https://pkg.go.dev/github.com/lafriks/http2#Server.ServeConn).
This is the typical setup behind a TLS-terminating load balancer:

```go
s := &fasthttp.Server{Handler: yourHandler}
h2s := http2.ConfigureServer(s, http2.ServerConfig{})

ln, err := net.Listen("tcp", ":8080")
if err != nil {
    log.Fatalln(err)
}

for {
    c, err := ln.Accept()
    if err != nil {
        break
    }

    // fails on connections that don't open with the HTTP/2 preface
    go h2s.ServeConn(c)
}
```

See [examples/h2c](./examples/h2c/main.go) for a complete example.

## How to use the client?

### Single host with HostClient

[ConfigureClient](https://pkg.go.dev/github.com/lafriks/http2#ConfigureClient) eagerly dials
the host, negotiates HTTP/2 via TLS ALPN, and installs an HTTP/2 transport on
the `HostClient`. It returns `ErrServerSupport` when the server doesn't speak
HTTP/2 (the `HostClient` is left unchanged and stays on HTTP/1.1).

```go
package main

import (
        "fmt"
        "log"

        "github.com/lafriks/http2"
        "github.com/valyala/fasthttp"
)

func main() {
        hc := &fasthttp.HostClient{
                Addr:  "api.binance.com:443",
        }

        if err := http2.ConfigureClient(hc, http2.ClientOpts{}); err != nil {
                log.Printf("%s doesn't support http/2\n", hc.Addr)
        }

        statusCode, body, err := hc.Get(nil, "https://api.binance.com/api/v3/time")
        if err != nil {
                log.Fatalln(err)
        }

        fmt.Printf("%d: %s\n", statusCode, body)
}
```

### Multi-host with fasthttp.Client

`fasthttp.Client` can upgrade individual backends to HTTP/2 through its
`ConfigureClient` hook. The hook is called once per backend host, under the
client's internal host-map lock:

```go
c := &fasthttp.Client{
    ConfigureClient: func(hc *fasthttp.HostClient) error {
        err := http2.ConfigureClient(hc, http2.ClientOpts{})
        if errors.Is(err, http2.ErrServerSupport) {
            return nil // host doesn't speak HTTP/2; keep HTTP/1.1
        }
        return err
    },
}
```

> **Locking caveat:** `ConfigureClient` dials the host eagerly inside the hook,
> which runs under the client's internal host-map lock. A slow or unreachable
> host will delay the first request to *every* other host for the duration of
> the TCP/TLS handshake. This is fine for a fixed set of known backends; for
> latency-sensitive clients talking to arbitrary or potentially unreachable
> hosts, use per-host `HostClient`s instead.

## Benchmarks

Benchmark code [here](https://github.com/lafriks/http2/tree/master/benchmark).

### fasthttp2

```console
$  h2load --duration=10 -c10 -m1000 -t 4 https://localhost:8443
[...]
finished in 10.01s, 533808.90 req/s, 33.09MB/s
requests: 5338089 total, 5348089 started, 5338089 done, 5338089 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 5338089 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 330.90MB (346976335) total, 137.45MB (144128403) headers (space savings 57.14%), 101.82MB (106761780) data
                     min         max         mean         sd        +/- sd
time for request:     1.06ms    101.25ms     17.16ms     11.06ms    75.19%
time for connect:     5.21ms     17.36ms     12.60ms      3.56ms    70.00%
time to 1st byte:    11.32ms     35.27ms     18.84ms      6.85ms    80.00%
req/s           :   48976.50    59084.92    53359.02     3657.52    60.00%
```

### net/http2

```console
$  h2load --duration=10 -c10 -m1000 -t 4 https://localhost:8443
[...]
finished in 10.01s, 124812.90 req/s, 5.00MB/s
requests: 1248129 total, 1258129 started, 1248129 done, 1248129 succeeded, 0 failed, 0 errored, 0 timeout
status codes: 1248247 2xx, 0 3xx, 0 4xx, 0 5xx
traffic: 50.00MB (52426258) total, 4.76MB (4995738) headers (space savings 95.83%), 23.81MB (24962580) data
                     min         max         mean         sd        +/- sd
time for request:      141us    140.75ms     19.69ms     11.34ms    76.79%
time for connect:     3.89ms     13.30ms      9.71ms      2.78ms    70.00%
time to 1st byte:    11.02ms     50.13ms     20.13ms     11.24ms    90.00%
req/s           :   11909.97    13162.89    12479.53      373.71    70.00%
```
