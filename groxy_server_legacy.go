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
	"strconv"
	"sync"
	"time"
)

var servLogLevel = Debug

func main() {
	localAddr := flag.String("localAddr", "127.0.0.1", "Address that this groxy server will listen at")
	localPort := flag.Int("localPort", 38620, "Port that this groxy server will listen on")
	certFile := flag.String("cert", "server.pem", "Certificate file that TLS requires, in PEM format")
	keyFile := flag.String("key", "server.key", "Key file for TLS encryption")
	isVerbose := flag.Bool("v", true, "Enable verbose output")
	isDebug := flag.Bool("d", true, "Enable debug level output")
	remoteAddr := flag.String("remoteAddr", "127.0.0.1", "Address that remote application exists")
	remotePort := flag.Int("remotePort", 55590, "Port that remote application exists")

	flag.Parse()

	config := ServerConfig{
		LocalAddr:   *localAddr,
		LocalPort:   *localPort,
		CertFile:    *certFile,
		KeyFile:     *keyFile,
		IsVerbose:   *isVerbose,
		IsDebugging: *isDebug,
		RemoteAddr:  *remoteAddr,
		RemotePort:  *remotePort,
	}

	if !IsValidIPv4Address(*localAddr) {
		fmt.Printf("Incorrect IP address for localAddr: %s\nExpected: Valid IPv4 address", *localAddr)
		return
	}
	if !IsValidIPv4Address(*remoteAddr) {
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

	//set clientLogLevel
	if *isDebug {
		servLogLevel = Debug
	} else if *isVerbose {
		servLogLevel = Info
	} else {
		servLogLevel = Silent
	}

	log.Println("groxy server started")
	if servLogLevel == Debug {
		log.Println("with args: ", config)
	}

	remoteConn, err := RemoteApplicationInit(config)
	defer remoteConn.Close()
	if err != nil {
		panic(err)
	}

	ServerInit(remoteConn, config)
}

func RemoteApplicationInit(config ServerConfig) (net.Conn, error) {
	listen, err := net.Listen("tcp4", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort))
	if err != nil {
		return nil, err
	}
	if servLogLevel >= Info {
		log.Println("RemoteApplicationInit::started listening at ", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort))
	}
	conn, err := listen.Accept()
	if err != nil {
		log.Fatal("RemoteApplicationInit::failed to connect to remote app: ", err)
	}
	if servLogLevel >= Silent {
		log.Printf("RemoteApplicationInit::connected to remote app at %s\n", conn.RemoteAddr().String())
	}
	return conn, nil
}

func ServerInit(remoteConn net.Conn, config ServerConfig) {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientListen, err := tls.Listen("tcp4", config.LocalAddr+":"+strconv.Itoa(config.LocalPort), tlsConf)
	if err != nil {
		panic("ServerInit::failed to TLS listen: " + err.Error())
	}

	defer func(clientListen net.Listener) {
		err := clientListen.Close()
		if err != nil {
			log.Println(err)
		}
	}(clientListen)

	for true {
		clientConn, err := clientListen.Accept()
		if err != nil {
			log.Println("ServerInit::failed to connect client from ", clientConn.RemoteAddr().String())
			continue
		}
		if servLogLevel >= Info {
			log.Println("ServerInit::accepted a client from ", clientConn.RemoteAddr().String())
		}
		go handleClient(clientConn, remoteConn)
	}

}

func handleClient(clientConn, remoteConn net.Conn) {
	var serverWg sync.WaitGroup
	serverWg.Add(1)

	relay := func(left, right net.Conn) error {
		defer serverWg.Done()

		var err, err1 error
		var wg sync.WaitGroup
		var wait = 100 * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(right, left)
			if servLogLevel == Debug {
				log.Printf("relay::forwarded %d bytes client->remote\n", n)
			}
			//err = right.SetReadDeadline(time.Now().Add(wait))
			//if err != nil {
			//	log.Printf("relay::failed to set read deadline for right @ %s: %v\n", right.RemoteAddr().String(), err)
			//}
		}()
		n, err := io.Copy(left, right)
		if servLogLevel == Debug {
			log.Printf("relay::forwarded %d bytes remote->client (err=:%s)\n", n, err)
		}
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
			log.Printf("relay::failed to close conn with client at %s: %v\n", left.RemoteAddr().String(), err)
		} else {
			log.Println("relay::disconnected from client")
		}
		return nil
	}

	go func() {
		err := relay(clientConn, remoteConn)
		if err != nil {
			log.Println("HandleClient::unexpected err from relay(): ", err)
		}
	}()

	serverWg.Wait()
	if servLogLevel >= Info {
		log.Println("HandleClient::finished client process and closed")
	}
}
