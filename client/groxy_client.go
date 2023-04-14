package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	. "go-test/common_def"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func clientProcess(clientConn net.Conn, config ClientConfig) {

	var clientWg sync.WaitGroup
	clientWg.Add(1)

	conf := &tls.Config{
		InsecureSkipVerify: config.AllowInsecureServerCert,
	}

	if config.IsMTLS {

		//TODO logs about loaded and server certs when logLevel >= Debug
		cert, err := ioutil.ReadFile("./certs/ca.crt")
		if err != nil {
			log.Fatalf("could not open certificate file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)

		clientCert := config.CertFile
		clientKey := config.KeyFile
		log.Println("Load key pairs - ", clientCert, clientKey)
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Fatalf("could not load certificate: %v", err)
		}

		conf.Certificates = []tls.Certificate{certificate}
		conf.RootCAs = caCertPool
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
	if config.LogLevel >= Debug {
		log.Printf("clientProcess::connect to remote %s:%d\n", config.RemoteAddr, config.RemotePort)

		log.Println("clientProcess::server certs:")
		certs := serverConn.ConnectionState().PeerCertificates
		for _, cert := range certs {
			log.Println("=====================================")
			log.Printf("Issuer Name: %s\n", cert.Issuer)
			log.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
			log.Printf("Common Name: %s \n", cert.Issuer.CommonName)
			log.Printf("Signature (first 8 bytes): %x ...\n", cert.Signature[:8])
			log.Println("=====================================")
		}
	}

	relay := func(left, right net.Conn) error {
		defer clientWg.Done()

		var err, err1 error
		var wg sync.WaitGroup
		var wait = 10 * time.Millisecond
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, _ := io.Copy(right, left)
			if config.LogLevel >= Debug {
				log.Printf("relay::forwarded %d bytes client<-serv\n", n)
			}
			err := right.SetReadDeadline(time.Now().Add(wait))
			if err != nil {
				log.Printf("relay::failed to set read deadline for right @ %s: %v\n", right.RemoteAddr().String(), err)
			}
		}()
		n, err := io.Copy(left, right)
		if config.LogLevel >= Debug {
			log.Printf("relay::forwarded %d bytes client->serv\n", n)
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
			log.Printf("relay::failed to close conn with server at %s: %v\n", left.RemoteAddr().String(), err)
		}
		if config.LogLevel >= Info {
			log.Printf("relay::closed conn with server at %s\n", left.RemoteAddr().String())
		}

		err = right.Close()
		if config.LogLevel >= Info {
			log.Printf("relay::closed conn with client at %s\n", right.RemoteAddr().String())
		}
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
	if config.LogLevel >= Info {
		log.Println("clientProcess::finished client process and connections all closed")
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
		if config.LogLevel >= Debug {
			log.Printf("ClientLoop::accepted from %s\n", conn.RemoteAddr().String())
		}
		// 启动一个单独的 goroutine 去处理连接
		go clientProcess(conn, config)
	}
}

func ClientMain() {
	localAddr := flag.String("localAddr", "127.0.0.1", "Address that groxy will listen at")
	remoteAddr := flag.String("remoteAddr", "127.0.0.1", "Address that groxy server at")
	localPort := flag.Int("localPort", 48620, "Port that groxy client listen on")
	remotePort := flag.Int("remotePort", 38620, "Port that groxy server listen on")
	insecureCertAllowed := flag.Bool("insecureCert", true, "Is insecure cert (self-signed cert) allowed on serverside")
	clientLogLevel := *flag.Int("logLevel", 2, "Logging level from 0 (quite) to 2 (debug)")
	isMTLS := flag.Bool("mtls", false, "Is mTLS enabled")
	caCert := flag.String("cacert", ".\\certs\\ca.crt", "CA cert used in mTLS mode")
	clientMode := flag.String("clientMode", "raw", "Client listen-and-proxying mode (raw, socks5, http)")
	cert := flag.String("cert", ".\\certs\\client.crt", "Cert that client holds in mTLS mode")
	key := flag.String("key", ".\\certs\\client.key", "Key that client holds in mTLS mode")

	flag.Parse()

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

	config := ClientConfig{
		LocalAddr:               *localAddr,
		LocalPort:               *localPort,
		RemotePort:              *remotePort,
		RemoteAddr:              *remoteAddr,
		AllowInsecureServerCert: *insecureCertAllowed,
		IsMTLS:                  *isMTLS,
		CACert:                  *caCert,
		LogLevel:                LogLevel(clientLogLevel),
		CertFile:                *cert,
		KeyFile:                 *key,
	}

	switch *clientMode {
	case "raw":
		config.ClientMode = ClientMode(Raw)
	case "socks5":
		config.ClientMode = ClientMode(Socks55)
	case "http":
		config.ClientMode = ClientMode(HTTP)
	}

	//TODO limited clientMode for now
	if config.ClientMode != Raw {
		log.Fatal("Only Raw mode is supported for now")
	}

	log.Println("groxy dev version started")
	log.Printf("args: ClientConfig=%#v\n", config)
	listener, err := ClientInit(config)
	if err != nil {
		panic(err)
	}
	ClientLoop(listener, config)
}
