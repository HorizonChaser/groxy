package serv

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	. "go-test/common_def"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

var legacyServLogLevel = Debug

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
		LocalAddr:  *localAddr,
		LocalPort:  *localPort,
		CertFile:   *certFile,
		KeyFile:    *keyFile,
		RemoteAddr: *remoteAddr,
		RemotePort: *remotePort,
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
		legacyServLogLevel = Debug
	} else if *isVerbose {
		legacyServLogLevel = Info
	} else {
		legacyServLogLevel = Silent
	}

	log.Println("groxy server started")
	if legacyServLogLevel == Debug {
		log.Println("with args: ", config)
	}

	remoteConn, err := remoteApplicationInit(config)
	defer remoteConn.Close()
	if err != nil {
		panic(err)
	}

	legacyServerInit(remoteConn, config)
}

func remoteApplicationInit(config ServerConfig) (net.Conn, error) {
	listen, err := net.Listen("tcp4", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort))
	if err != nil {
		return nil, err
	}
	if legacyServLogLevel >= Info {
		log.Println("remoteApplicationInit::started listening at ", config.RemoteAddr+":"+strconv.Itoa(config.RemotePort))
	}
	conn, err := listen.Accept()
	if err != nil {
		log.Fatal("remoteApplicationInit::failed to connect to remote app: ", err)
	}
	if legacyServLogLevel >= Silent {
		log.Printf("remoteApplicationInit::connected to remote app at %s\n", conn.RemoteAddr().String())
	}
	return conn, nil
}

func legacyServerInit(remoteConn net.Conn, config ServerConfig) {
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}
	clientListen, err := tls.Listen("tcp4", config.LocalAddr+":"+strconv.Itoa(config.LocalPort), tlsConf)
	if err != nil {
		panic("legacyServerInit::failed to TLS listen: " + err.Error())
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
			log.Println("legacyServerInit::failed to connect client from ", clientConn.RemoteAddr().String())
			continue
		}
		if legacyServLogLevel >= Info {
			log.Println("legacyServerInit::accepted a client from ", clientConn.RemoteAddr().String())
		}
		go legacyHandleClient(clientConn, remoteConn)
	}

}

func legacyHandleClient(clientConn, remoteConn net.Conn) {
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
			if legacyServLogLevel == Debug {
				log.Printf("relay::forwarded %d bytes client->remote\n", n)
			}
			//err = right.SetReadDeadline(time.Now().Add(wait))
			//if err != nil {
			//	log.Printf("relay::failed to set read deadline for right @ %s: %v\n", right.RemoteAddr().String(), err)
			//}
		}()
		n, err := io.Copy(left, right)
		if legacyServLogLevel == Debug {
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
	if legacyServLogLevel >= Info {
		log.Println("HandleClient::finished client process and closed")
	}
}
