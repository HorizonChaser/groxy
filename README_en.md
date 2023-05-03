# groxy: a TCP proxy encrypted with TLS in Golang

groxy is a simple transparent TCP proxy encrypted by TLS. It can create a tunnel between client and server side, data in which would be protected by TLS.

The server side and client side groxy will each expose one port for applications wishing to use to connect with.

## Current Progress

- [x] Implement TCP tunnel
- [x] Support SOCKS5 proxy
- [x] Support HTTP proxy (not likely to be implemented)
- [ ] Capture and forward all TCP traffic on client side
  - possibly implemented by using TUN device and route table hooking
- [x] Use a connection pool to optimize performance
- [x] Benchmark

## Usage

## Client Side

```shell
./groxy_client --help
Usage of groxy_client:
  -insecureCert
        Is insecure cert (self-signed cert) allowed on serverside (default true)
  -localAddr string
        Address that groxy will listen at (default "127.0.0.1")
  -localPort int
        Port that groxy client listen on (default 48620)
  -logLevel int
        Log verbosity, 1~3 from low to high (default 3)
  -remoteAddr string
        Address that groxy server at (default "127.0.0.1")
  -remotePort int
        Port that groxy server listen on (default 38620)
```

## Server Side

```shell
./groxy_server --help
Usage of groxy_server:
  -cert string
        Certificate file that TLS requires, in PEM format (default "server.pem")
  -d    Enable debug level output (default true)
  -key string
        Key file for TLS encryption (default "server.key")
  -localAddr string
        Address that this groxy server will listen at (default "127.0.0.1")
  -localPort int
        Port that this groxy server will listen on (default 38620)
  -remoteAddr string
        Address that remote application exists (default "127.0.0.1")
  -remotePort int
        Port that remote application exists (default 55590)
  -v    Enable verbose output (default true)
```

To be noticed that the certificate should be in `pem` format.

For reference:

Using `openssl` to create private key

`openssl genrsa -out server.key 2048`

Generating certificate

`openssl req -new -x509 -key server.key -out server.pem -days 3650`

## Build

```shell
git clone github.com/HorizonChaser/groxy
cd groxy
go env -w GOOS=windows
go env -w GOARCH=amd64

#Server side
go build ./groxy_server.go ./common_def.go

#Client side
go build ./groxy_client.go ./common_def.go
```
