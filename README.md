# groxy: 使用 Go 与 TLS 实现的 TCP 代理

[English README](README_en.md)

groxy 是一个简单的使用 TLS 加密的 TCP 代理, 它会在服务器端与客户端之间建立一条隧道, 这之间传输的数据通过 TLS 进行保护.

服务器端与客户端各自对外暴露一个端口供外层的应用程序连接.

## 当前的进度

- [x] TCP 连接隧道的实现 
- [ ] 支持 SOCKS5 代理
- [ ] 支持 HTTP 代理 (很可能不会实现)
- [ ] 捕获客户端所有 TCP 流量
  - 可能使用 TUN 配合路由表劫持
- [ ] 使用连接池提高性能
- [ ] 性能测试

## 使用

### 客户端

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

### 服务器端

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

注意证书需要是 pem 格式

仅供参考: 

使用 `openssl` 生成私钥  

`openssl genrsa -out server.key 2048`

生成证书  

`openssl req -new -x509 -key server.key -out server.pem -days 3650`

## 构建

```shell
git clone github.com/HorizonChaser/groxy
cd groxy
go env -w GOOS=windows
go env -w GOARCH=amd64

#构建服务端
go build ./groxy_server.go ./common_def.go

#构建客户端
go build ./groxy_client.go ./common_def.go
```
