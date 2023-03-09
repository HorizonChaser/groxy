package main

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

type ClientConfig struct {
	LocalAddr      string
	LocalPort      int
	RemoteAddr     string
	RemotePort     int
	CACertFile     string
	CAKeyFile      string
	ClientCertFile string   // client cert for mTLS
	ClientKeyFile  string   // client private key for mTLS
	IPS            []string // IPAddress for the child cert
	Names          []string // DNSNames for the child cert
	Quiet          bool
}

const (
	Silent = iota
	Info
	Debug
)

var logLevel = Debug

func clientProcess(clientConn net.Conn, config ClientConfig) {

	var wg sync.WaitGroup
	wg.Add(2)

	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	serverConn, err := tls.Dial("tcp", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort), conf)
	if err != nil {
		log.Println(err)
		return
	}
	if logLevel == Debug {
		log.Printf("clientProcess::connect to remote %s:%d\n", config.RemoteAddr, config.RemotePort)
	}

	//forward := func(src, dest net.Conn, isFromServer bool) {
	//
	//	n, err := io.Copy(dest, src)
	//	if err != nil {
	//		if isFromServer {
	//			log.Printf("clientProcess::failed to forward from serv to client: %v\n", err)
	//		} else {
	//			log.Printf("clientProcess::failed to forward from client to serv: %v\n", err)
	//		}
	//		return
	//	}
	//	if logLevel == Debug {
	//		log.Printf("clientProcess::forwarding %d bytes from", n)
	//	}
	//	if isFromServer {
	//		log.Println("serv to client")
	//	} else {
	//		log.Println("client to serv")
	//	}
	//	wg.Done()
	//}
	//
	//go forward(serverConn, clientConn, true)
	//go forward(clientConn, serverConn, false)

	relay := func(left, right net.Conn) error {
		var err, err1 error
		var wg sync.WaitGroup
		var wait = 1 * time.Second
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err1 = io.Copy(right, left)
			right.SetReadDeadline(time.Now().Add(wait))
		}()
		_, err = io.Copy(left, right)
		left.SetReadDeadline(time.Now().Add(wait))
		wg.Wait()

		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}

		if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
			return err1
		}

		left.Close()
		right.Close()

		return nil
	}

	go relay(serverConn, clientConn)
	//go relay(clientConn, serverConn)

	wg.Wait()
	err = clientConn.Close()
	log.Printf("clientProcess::closed client conn at %s\n", clientConn.RemoteAddr().String())
	serverConn.Close()
	if err != nil {
		log.Printf("clientProcess::failed to close conn with client at %s: %v\n", clientConn.RemoteAddr().String(), err)
	}

}

func ClientInit(config ClientConfig) (net.Listener, error) {
	// 建立 tcp 服务
	listen, err := net.Listen("tcp4", config.LocalAddr+":"+strconv.Itoa(config.LocalPort))
	if err != nil {
		return nil, err
	}
	return listen, nil
}

func ClientLoop(listen net.Listener, config ClientConfig) {
	for {
		// 等待客户端建立连接
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		if logLevel >= Info {
			log.Printf("ClientLoop::accepted from %s\n", conn.RemoteAddr().String())
		}
		// 启动一个单独的 goroutine 去处理连接
		go clientProcess(conn, config)
	}
}

func main() {
	config := ClientConfig{
		LocalAddr:  "127.0.0.1",
		LocalPort:  48620,
		RemotePort: 38620,
		RemoteAddr: "127.0.0.1",
	}
	log.Println("groxy dev version started")
	log.Printf("args: ClientConfig=%#v\n", config)
	listener, err := ClientInit(config)
	if err != nil {
		panic(err)
	}
	ClientLoop(listener, config)
}
