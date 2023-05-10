package serv

import (
	"crypto/tls"
	"crypto/x509"
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

/*
some notes about differences between .key, .pem and .crt files

.key files are generally the private key, used by the server to encrypt and package data for verification by clients.

.pem files are generally the public key, used by the client to verify and decrypt data sent by servers. PEM files could also be encoded private keys, so check the content if you're not sure.

.p12 files have both halves of the key embedded, so that administrators can easily manage halves of keys.

.cert or .crt files are the signed certificates -- basically the "magic" that allows certain sites to be marked as trustworthy by a third party.
*/

// parseServerCArgs parses options form command line arguments
func parseServerCArgs() *ServerConfig {
	localAddr := flag.String("localAddr", "127.0.0.1", "Address that this groxy server will listen at")
	localPort := flag.Int("localPort", 38620, "Port that this groxy server will listen on")
	certFile := flag.String("cert", ".\\certs\\server.pem", "Certificate file that TLS requires, in PEM format")
	keyFile := flag.String("key", ".\\certs\\server.key", "Key file for TLS encryption")
	remoteAddr := flag.String("remoteAddr", "127.0.0.1", "Address that remote application exists")
	remotePort := flag.Int("remotePort", 55590, "Port that remote application exists")
	servLogLevel := *flag.Int("logLevel", 2, "Logging level from 0 (quite) to 2 (debug)")
	isMTLS := flag.Bool("mtls", false, "Is mTLS enabled")
	serverMode := flag.String("serverMode", "dynamic", "Server Mode (dynamic or legacy)")
	caCert := flag.String("cacert", ".\\certs\\ca.crt", "CA cert used in mTLS mode")
	isKeyLoggerEnabled := flag.Bool("keyLogger", false, "Is key logger enabled (FOR AUDIT PURPOSE ONLY)")
	keyLoggerPath := flag.String("keyloggerPath", ".\\TLS_KEY_LOG", "Key logger file path (FOR AUDIT PURPOSE ONLY)")

	flag.Parse()

	config := ServerConfig{
		LocalAddr:   *localAddr,
		LocalPort:   *localPort,
		CertFile:    *certFile,
		KeyFile:     *keyFile,
		LogLevel:    LogLevel(servLogLevel),
		RemoteAddr:  *remoteAddr,
		RemotePort:  *remotePort,
		IsMTLS:      *isMTLS,
		CACert:      *caCert,
		IsKeyLogged: *isKeyLoggerEnabled,
		KeyLogger:   *keyLoggerPath,
	}

	switch *serverMode {
	case "legacy":
		config.ServerMode = Legacy
	case "dynamic":
		config.ServerMode = Dynamic
	case "realtime":
		config.ServerMode = Realtime
	default:
		fmt.Printf("Incorrect value for serverMode: %s\nExpected: dynamic or legacy", *serverMode)
		return nil
	}

	// ensure IPv4 addr and port in config are all valid
	if !IsValidIPv4Address(*localAddr) {
		fmt.Printf("Incorrect IP address for localAddr: %s\nExpected: Valid IPv4 address", *localAddr)
		return nil
	}
	if !IsValidIPv4Address(*remoteAddr) {
		fmt.Printf("Incorrect IP address for remoteAddr: %s\nExpected: Valid IPv4 address", *localAddr)
		return nil
	}
	if *localPort <= 0 || *localPort >= 65536 {
		fmt.Printf("Invalid port for localPort: %d\nExpected: Valid port in [1,65535]", *localPort)
		return nil
	}
	if *remotePort <= 0 || *remotePort >= 65536 {
		fmt.Printf("Invalid port for localPort: %d\nExpected: Valid port in [1,65535]", *localPort)
		return nil
	}

	return &config
}

// serverDconnInit creates a TLS listener on port and addr according to config, which accepts TLS connection from groxy client
func serverDconnInit(config ServerConfig) {
	// load certs used in TLS handshake
	cert, err := tls.LoadX509KeyPair(config.CertFile, config.KeyFile)
	if err != nil {
		panic(err)
	}

	var tlsConf *tls.Config
	tlsConf.MinVersion = tls.VersionTLS13 // set to TLS 1.3 according to the thesis

	if config.IsMTLS {
		// load CA certificate file and add it to list of client CAs
		caCertFile, err := os.ReadFile(config.CACert)
		if err != nil {
			log.Fatalf("error reading CA certificate: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCertFile)

		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert, // client MUST provide cert in mTLS mode
		}
	} else {
		tlsConf.Certificates = []tls.Certificate{cert}
	}

	if config.IsKeyLogged {
		f, err := os.OpenFile(config.KeyLogger, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		defer f.Close()

		tlsConf.KeyLogWriter = f
	}

	// listen TLS connections on specific port and addr
	clientListen, err := tls.Listen("tcp4", config.LocalAddr+":"+strconv.Itoa(config.LocalPort), tlsConf)
	if err != nil {
		panic("handleClient::failed to TLS listen: " + err.Error())
	}

	for true {
		clientConn, err := clientListen.Accept()
		if err != nil {
			log.Println("serverDconnInit::failed to connect client from ", clientConn.RemoteAddr().String())
			continue
		}
		if config.LogLevel >= Info {
			log.Println("serverDconnInit::accepted a client from ", clientConn.RemoteAddr().String())
		}
		go handleClient(clientConn, config)
	}
}

// handleClient reads from groxy clients' TLS connections, and forwards decrypted TLS traffic towards remote addr and ports set in config
func handleClient(clientConn net.Conn, config ServerConfig) {

	defer func(clientConn net.Conn) {
		err := clientConn.Close()
		if err != nil && err.Error() != "use of closed network connection" {
			log.Printf("failed to close client conn: %s\n", err)
		}
	}(clientConn)

	tlsConn, ok := clientConn.(*tls.Conn)
	if !ok {
		log.Printf("handleClient::invalid mTLS connection with %s\n", clientConn.RemoteAddr().String())
		clientConn.Close()
		return
	}

	if config.IsMTLS && config.LogLevel >= Debug {
		//We need to manually do handshake before we see the client cert
		if err := tlsConn.Handshake(); err != nil {
			fmt.Printf("handleClient: client handshake err %+v \n\n", err)
			return
		}

		certs := tlsConn.ConnectionState().PeerCertificates
		log.Printf("handleClient::client from %s has certs below:\n", clientConn.RemoteAddr().String())
		for _, cert := range certs {
			log.Println("=====================================")
			log.Printf("Issuer Name: %s\n", cert.Issuer)
			log.Printf("Expiry: %s \n", cert.NotAfter.Format("2006-January-02"))
			log.Printf("Common Name: %s \n", cert.Issuer.CommonName)
			log.Printf("Signature (first 8 bytes): %x ...\n", cert.Signature[:8])
			log.Println("=====================================")
		}
	}

	remoteAddr := config.RemoteAddr + ":" + strconv.Itoa(config.RemotePort)

	// Realtime mode means Gproto CONNECT message is used to convey remote addr and port,
	// so we need to read, parse and use these from this message instead of which set in config
	if config.ServerMode == Realtime {
		buf := make([]byte, 256)

		n, err := io.ReadFull(clientConn, buf[:5])
		if err != nil {
			log.Printf("Insuffcient bytes read: got %d , expected 2 for now\n", n)
			return
		}

		// Gproto version field
		if buf[0] != 0x86 || buf[1] != 0x20 {
			log.Printf("Version field corrputed: got %#v\n", buf[:2])
			return
		}

		// Gproto command field
		if buf[2] != 0x10 {
			log.Printf("Corrputed cmd: %#v\n", buf[2])
			return
		}

		//addrType := buf[3]
		addrLen := buf[4]
		n, err = io.ReadFull(clientConn, buf[5:5+addrLen])
		if n != int(addrLen) {
			log.Printf("Corrupted Addr: no enough bytes")
			return
		}

		// set remoteAddr as what we parsed from Gproto message
		remoteAddr = string(buf[5 : 5+addrLen])
	}

	if config.LogLevel >= Info {
		log.Printf("remoteAddr Parsed: %s\n", remoteAddr)
	}

	// connect to remote addr
	remoteConn, err := net.Dial("tcp", remoteAddr)
	defer func(remoteConn net.Conn) {
		if remoteConn == nil {
			return
		}

		err := remoteConn.Close()
		if err != nil {
			log.Printf("failed to close remote conn: %s\n", err)
		}
	}(remoteConn)

	if err != nil {
		err1 := clientConn.Close()
		log.Printf("handleClient::failed to connect to remote app: %s\n", err)
		if err1 != nil {
			log.Printf("During failed to connect to remote, we also failed to close client conn: %s\n", err1)
		}
		return
	} else {
		// if Gproto is enabled, we need to tell the groxy client
		// that we've successfully connected to the required remote addr
		if config.ServerMode == Realtime {
			retMsg := GprotoConnMsg{
				Ver:     [2]byte{0x86, 0x20},
				Command: 0x20,
				Status:  0,
			}
			n, err := clientConn.Write(retMsg.ToByteSlice())
			if err != nil || n != 4 {
				log.Printf("Failed to respond to client with gproto msg\n")
				log.Printf("err=%v, n=%d\n", err, n)
				return
			}
		}
	}

	var serverWg sync.WaitGroup
	serverWg.Add(1)

	// finish the bidirectional forwarding jobs, as always as pleasure :)
	relay := func(left, right net.Conn) error {
		defer serverWg.Done()

		var err, err1 error
		var wg sync.WaitGroup
		var wait = 10 * time.Millisecond
		wg.Add(1)
		go func(config ServerConfig) {
			defer wg.Done()
			n, _ := io.Copy(right, left)
			if config.LogLevel == Debug {
				log.Printf("relay::forwarded %d bytes client->remote\n", n)
			}
			//err = right.SetReadDeadline(time.Now().Add(wait))
			//if err != nil {
			//	log.Printf("relay::failed to set read deadline for right @ %s: %v\n", right.RemoteAddr().String(), err)
			//}
		}(config)
		n, err := io.Copy(left, right)
		if config.LogLevel == Debug {
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
			if config.LogLevel >= Debug {
				log.Println("relay::disconnected from client")
			}
		}
		return nil
	}

	go func() {
		err := relay(clientConn, remoteConn)
		if err != nil {
			log.Println("handleClient::unexpected err from relay(): ", err)
		}
	}()

	serverWg.Wait()
	if config.LogLevel >= Info {
		log.Println("handleClient::finished client process and closed")
	}
}

// ServMain is the main entrance for server part, which is modified from Main func in previous version of groxy server
func ServMain() {
	PrintServerWelcomeMsg("Horizon Groxy Server Dev version", "0.3.0-dev")
	serverConfig := parseServerCArgs()

	if serverConfig == nil {
		fmt.Printf("Failed to parse args, exiting...\n")
		return
	}

	log.Print("server started with args= ")
	log.Printf("%#v\n", *serverConfig)

	// let's begin our job from here, say farewell the ServMain func as we will never come back
	serverDconnInit(*serverConfig)
}
