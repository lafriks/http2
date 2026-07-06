# HTTP2

http2 is an implementation of HTTP/2 protocol for [fasthttp](https://github.com/valyala/fasthttp).

Fork from [github.com/dgrr/http2](https://github.com/dgrr/http2)

## Download

```bash
go get github.com/lafriks/http2@v0.3.5
```

## Help

If you need any help to set up, contributing or understanding this repo, you can contact me on [gofiber's Discord](https://gofiber.io/discord).

## How to use the server?

The server can only be used if your server supports TLS.
Then, you can call [ConfigureServer](https://pkg.go.dev/github.com/lafriks/http2#ConfigureServer).

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

## How to use the client?

The HTTP/2 client only works with the HostClient.

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
