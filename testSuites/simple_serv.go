package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"
)

func tcpServ() {
	listen, err := net.Listen("tcp4", "127.0.0.1:38620")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			panic(err)
		}
		log.Printf("Accepting from %s\n", conn.RemoteAddr().String())

		go func(conn2 net.Conn) {
			defer conn.Close()
			conn.Write([]byte("Hellowww\n"))
			log.Printf("Served geusts at %s\n", conn.LocalAddr().String())
		}(conn)

	}
}

func getCertInfo(path string) pkix.Name {
	// Load the certificate file
	certBytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("Failed to read certificate file:", err)
		return pkix.Name{}
	}

	// Parse the certificate
	block, _ := pem.Decode(certBytes)
	if block == nil {
		fmt.Println("Failed to decode certificate PEM")
		return pkix.Name{}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate:", err)
		return pkix.Name{}
	}

	// Extract the country name from the certificate

	return cert.Subject
}

func tlsServ() {
	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	certInfo := getCertInfo("server.pem")
	if err != nil {
		panic(err)
	}

	log.Printf("Simple TLS server started with cert containing\n%v\n", certInfo)

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp4", ":38620", config)
	if err != nil {
		log.Println(err)
		return
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go handleConn(conn)
	}

}

func handleConn(conn net.Conn) {
	defer func() {
		conn.Close()
		log.Println("conn closed")
	}()
	_, err := conn.Write([]byte("Hellowww\n"))
	log.Printf("Served %s\n", conn.RemoteAddr().String())
	if err != nil {
		log.Printf("handleConn::failed to write resp for conn to %s\n", conn.RemoteAddr().String())
	}

	for {
		err = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			log.Println(err)
			return
		}
		read := make([]byte, 64)
		_, err = conn.Read(read)
		if err != nil {
			log.Println("reached waiting limit")
			conn.Write([]byte("See you again!\n"))
			return
		}
		log.Printf("handleConn::received %s    from %s\n", read, conn.RemoteAddr().String())
		conn.Write([]byte("wow, I received " + string(bytes.TrimSpace(read)) + " from you!\n"))
	}
}

func main() {
	mode := flag.String("mode", "tls", "the mode for simpleServ (tls or tcp)")
	flag.Parse()

	if *mode == "tls" {
		tlsServ()
	}
	if *mode == "tcp" {
		tcpServ()
	}

}
