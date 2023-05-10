package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
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

// clientProcess connects to server in config, and then simply forward data between client and server
func clientProcess(clientConn net.Conn, config ClientConfig) {

	// used to wait for both sides closing conns
	var clientWg sync.WaitGroup
	clientWg.Add(1)

	// since our cert is self-signed, so we need to allow Insecure server side certs
	conf := &tls.Config{
		InsecureSkipVerify: config.AllowInsecureServerCert,
	}

	if config.IsMTLS {

		//TODO logs about loaded and server certs when logLevel >= Debug
		cert, err := os.ReadFile("./certs/ca.crt")
		if err != nil {
			log.Fatalf("could not open certificate file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)

		clientCert := config.CertFile
		clientKey := config.KeyFile
		if config.LogLevel >= Debug {
			log.Println("Load key pairs - ", clientCert, clientKey)
		}
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			log.Fatalf("could not load certificate: %v", err)
		}

		conf.Certificates = []tls.Certificate{certificate}
		conf.RootCAs = caCertPool
	}

	// connect to server in TLS
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

	// relay performs forwarding jobs actually
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

	// wait for both sides close conns
	clientWg.Wait()
	if config.LogLevel >= Info {
		log.Println("clientProcess::finished client process and connections all closed")
	}
}

// clientInit creates a listener on given addr and port in RAW mode
func clientInit(config ClientConfig) (net.Listener, error) {
	// 建立 tcp 服务
	listen, err := net.Listen("tcp4", config.LocalAddr+":"+strconv.Itoa(config.LocalPort))
	if err != nil {
		return nil, err
	}
	return listen, nil
}

// clientLoopRaw loops to accept conns from client, and then clientProcess will handle forwarding jobs
func clientLoopRaw(listen net.Listener, config ClientConfig) {
	for {
		// 等待客户端建立连接
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		if config.LogLevel >= Debug {
			log.Printf("clientLoopRaw::accepted from %s\n", conn.RemoteAddr().String())
		}
		// 启动一个单独的 goroutine 去处理连接
		go clientProcess(conn, config)
	}
}

// clientLoopSocks5 loops and accept client SOCKS5 requests
func clientLoopSocks5(listen net.Listener, config ClientConfig) {
	for {
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		if config.LogLevel >= Debug {
			log.Printf("clientLoopSocks5::TCP from %s\n", conn.RemoteAddr().String())
		}

		go clientSocks5Process(conn, config)
	}
}

// clientSocks5Process grants authorization to SOCKS5 client, and parse destination addr and port from SOCKS5 CONNECT request,
// which would be sent in Gproto message, and finally do the forwarding jobs
func clientSocks5Process(clientConn net.Conn, config ClientConfig) {
	if err := clientSocks5Auth(clientConn); err != nil {
		//TODO log
		return
	}

	destAddr, err := clientSocks5ParseAddrPort(clientConn)
	if err != nil {
		//TODO log
		return
	}

	msg := GprotoAddrMsg{
		Ver:      [2]byte{0x86, 0x20},
		Command:  0x10,
		AddrType: 0x14,
		AddrLen:  byte(len(destAddr)),
		Addr:     []byte(destAddr),
	}

	var clientWg sync.WaitGroup
	clientWg.Add(1)

	conf := &tls.Config{
		InsecureSkipVerify: config.AllowInsecureServerCert,
	}

	if config.IsMTLS {

		//TODO logs about loaded and server certs when logLevel >= Debug
		cert, err := os.ReadFile("./certs/ca.crt")
		if err != nil {
			log.Fatalf("could not open certificate file: %v", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(cert)

		clientCert := config.CertFile
		clientKey := config.KeyFile
		if config.LogLevel >= Debug {
			log.Println("Load key pairs - ", clientCert, clientKey)
		}
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

	_, err = serverConn.Write(msg.ToByteSlice())
	if err != nil {
		//TODO log
		return
	}

	// read Gproto returned message from server
	buffer := make([]byte, 4)
	n, err := serverConn.Read(buffer)
	if err != nil || n != 4 {
		//TODO log
		return
	}

	// if Gproto says the connection couldn't be established
	if !bytes.Equal(buffer, []byte{0x86, 0x20, 0x20, 0x00}) {
		//TODO log and proper handle
		return
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

// clientSocks5Auth does the auth job of SOCKS5 proto,
// currently Groxy doesn't support SOCKS5 auth, but can be easily added later
func clientSocks5Auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	// read VER and NMETHODS fields
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// read METHODS list
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	// currently, groxy doesn't require any auth inside SOCKS5
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp: " + err.Error())
	}

	return nil
}

// clientSocks5ParseAddrPort parses addr and port from SOCKS5 CONNECT message sent from client
func clientSocks5ParseAddrPort(client net.Conn) (string, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return "", errors.New("read header: " + err.Error())
	}

	// check ver and command field
	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return "", errors.New("invalid ver/cmd")
	}

	addr := ""
	switch atyp {
	case 1: //IPv4
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return "", errors.New("invalid IPv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	case 3: //hostname
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return "", errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return "", errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4: // IPv6, not implemented yet
		return "", errors.New("IPv6: not supported yet")

	default:
		return "", errors.New("invalid atyp")
	}

	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return "", errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	destAddrPort := fmt.Sprintf("%s:%d", addr, port)

	// return the message that connection has been established
	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		//TODO log
		return "", err
	}

	return destAddrPort, nil
}

// clientLoopHttp loops to accept HTTP proxy request
func clientLoopHttp(listener net.Listener, config ClientConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		if config.LogLevel >= Debug {
			log.Printf("clientLoopSocks5::TCP from %s\n", conn.RemoteAddr().String())
		}

		go clientHttpProcess(conn, config)
	}
}

// clientHttpProcess handles HTTP proxy request, which should use CONNECT method
func clientHttpProcess(conn net.Conn, config ClientConfig) {
	// 用来存放客户端数据的缓冲区
	var b [1024]byte
	//从客户端获取数据
	n, err := conn.Read(b[:])
	if err != nil {
		log.Println(err)
		return
	}

	var method, URL, address string
	// 从客户端数据读入 method，url
	_, err = fmt.Sscanf(string(b[:bytes.IndexByte(b[:], '\n')]), "%s%s", &method, &URL)
	if err != nil {

		return
	}
	hostPortURL := (URL)

	if method == "CONNECT" {
		address = hostPortURL
	} else {
		conn.Write([]byte("HTTP/1.0 405 Method Not Allowed"))
		conn.Close()
		return
	}

	msg := GprotoAddrMsg{
		Ver:      [2]byte{0x86, 0x20},
		Command:  0x10,
		AddrType: 0x14,
		AddrLen:  byte(len(address)),
		Addr:     []byte(address),
	}

	var clientWg sync.WaitGroup
	clientWg.Add(1)

	conf := &tls.Config{
		InsecureSkipVerify: config.AllowInsecureServerCert,
	}

	if config.IsMTLS {

		//TODO logs about loaded and server certs when logLevel >= Debug
		cert, err := os.ReadFile("./certs/ca.crt")
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

	clientConn := conn

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

	_, err = serverConn.Write(msg.ToByteSlice())
	if err != nil {
		//TODO log
		conn.Write([]byte("HTTP/1.0 500 Internal Error"))
		conn.Close()
		return
	}

	buffer := make([]byte, 4)
	n, err = serverConn.Read(buffer)
	if err != nil || n != 4 {
		//TODO log
		conn.Write([]byte("HTTP/1.0 500 Internal Error"))
		conn.Close()
		return
	}
	if !bytes.Equal(buffer, []byte{0x86, 0x20, 0x20, 0x00}) {
		//TODO log
		conn.Write([]byte("HTTP/1.0 500 Internal Error"))
		conn.Close()
		return
	}

	// tell client that the proxy has been successfully set up
	conn.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))

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

// ClientMain is the main entrance for client part, which is modified from Main func in previous version of groxy client
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

	// ensure IPv4 addr and port in config are all valid
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

	log.Println("groxy dev version started")
	log.Printf("args: ClientConfig=%#v\n", config)
	listener, err := clientInit(config)
	if err != nil {
		panic(err)
	}

	// dispatch to different Loop func according to mode set in config
	if config.ClientMode == Raw {
		clientLoopRaw(listener, config)
	}
	if config.ClientMode == Socks55 {
		clientLoopSocks5(listener, config)
	}
	if config.ClientMode == HTTP {
		clientLoopHttp(listener, config)
	}
}
