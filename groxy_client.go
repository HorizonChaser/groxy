package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type ClientConfig struct {
	LocalAddr               string
	LocalPort               int
	RemoteAddr              string
	RemotePort              int
	AllowInsecureServerCert bool
}

const (
	Silent = iota
	Info
	Debug
)

var logLevel = Debug

func clientProcess(clientConn net.Conn, config ClientConfig) {

	var clientWg sync.WaitGroup
	clientWg.Add(1)

	conf := &tls.Config{
		InsecureSkipVerify: config.AllowInsecureServerCert,
	}
	serverConn, err := tls.Dial("tcp", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort), conf)
	if err != nil {
		log.Printf("clientProcess::failed to connect to server at %s: ", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort))
		log.Println(err)
		err := clientConn.Close()
		if err != nil {
			log.Printf("clientProcess::failed to close conn with client at %s: %v\n", clientConn.RemoteAddr().String(), err)
			return
		}
		return
	}
	if logLevel == Debug {
		log.Printf("clientProcess::connect to remote %s:%d\n", config.RemoteAddr, config.RemotePort)
	}

	relay := func(left, right net.Conn) error {
		defer clientWg.Done()

		var err, err1 error
		var wg sync.WaitGroup
		var wait = 500 * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err1 = io.Copy(right, left)
			err := right.SetReadDeadline(time.Now().Add(wait))
			if err != nil {
				log.Printf("relay::failed to set read deadline for right @ %s: %v\n", right.RemoteAddr().String(), err)
			}
		}()
		_, err = io.Copy(left, right)
		err = left.SetReadDeadline(time.Now().Add(wait))
		if err != nil {
			log.Printf("relay::failed to set read deadline for left @ %s: %v\n", right.RemoteAddr().String(), err)
		}
		wg.Wait()

		if err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
			return err
		}

		if err1 != nil && !errors.Is(err1, os.ErrDeadlineExceeded) {
			return err1
		}

		err = left.Close()
		if err != nil {
			log.Printf("relay::failed to close conn with server at %s: %v\n", left.RemoteAddr().String(), err)
		}
		log.Printf("relay::closed conn with server at %s\n", left.RemoteAddr().String())

		err = right.Close()
		log.Printf("relay::closed conn with client at %s\n", right.RemoteAddr().String())
		if err != nil {
			log.Printf("relay::failed to close conn with client at %s: %v\n", right.RemoteAddr().String(), err)
		}
		return nil
	}

	go func() {
		err := relay(serverConn, clientConn)
		if err != nil {
			log.Printf("clientProcess::unexpected err thrown from relay(): %v\n", err)
		}
	}()

	clientWg.Wait()
	log.Println("clientProcess::finished client process and connections all closed")
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
	localAddr := flag.String("localAddr", "127.0.0.1", "Address that groxy will listen at")
	remoteAddr := flag.String("remoteAddr", "127.0.0.1", "Address that groxy server at")
	localPort := flag.Int("localPort", 48620, "Port that groxy client listen on")
	remotePort := flag.Int("remotePort", 38620, "Port that groxy server listen on")
	insecureCertAllowed := flag.Bool("insecureCert", true, "Is insecure cert (self-signed cert) allowed on serverside")
	logLevel = *flag.Int("logLevel", 3, "Log verbosity, 1~3 from low to high")
	flag.Parse()

	ipReg := `^((0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.){3}(0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])$`
	r, _ := regexp.Compile(ipReg)
	if !r.MatchString(*localAddr) {
		fmt.Printf("Incorrect IP address for localAddr: %s\nExpected: Valid IPv4 address", *localAddr)
		return
	}
	if !r.MatchString(*remoteAddr) {
		fmt.Printf("Incorrect IP address for remoteAddr: %s\nExpected: Valid IPv4 address", *localAddr)
		return
	}
	if *localPort <= 0 || *localPort >= 65536 {
		fmt.Printf("Invalid port for localPort: %d\nExpected: Valid port in [1,65535]", *localPort)
		return
	}
	if *remotePort <= 0 || *remotePort >= 65536 {
		fmt.Printf("Invalid port for localPort: %d\nExpected: Valid port in [1,65535]", *localPort)
		return
	}

	config := ClientConfig{
		LocalAddr:               *localAddr,
		LocalPort:               *localPort,
		RemotePort:              *remotePort,
		RemoteAddr:              *remoteAddr,
		AllowInsecureServerCert: *insecureCertAllowed,
	}
	log.Println("groxy dev version started")
	log.Printf("args: ClientConfig=%#v\n", config)
	listener, err := ClientInit(config)
	if err != nil {
		panic(err)
	}
	ClientLoop(listener, config)
}
