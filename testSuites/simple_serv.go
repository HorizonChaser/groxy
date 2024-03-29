package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/unrolled/secure"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// tcpServ writes "Hellowww" to incoming TCP conn and read up to 256 bytes before close
func tcpServ() {
	listen, err := net.Listen("tcp4", "127.0.0.1:55590")
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
			for true {
				read := make([]byte, 256)
				err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				if err != nil {
					return
				}
				_, err = conn.Read(read)
				if err != nil {
					return
				}
				_, err = conn.Write([]byte("wow, I received " + string(bytes.TrimSpace(read)) + " from you!\n"))
				if err != nil {
					return
				}
			}
		}(conn)

	}
}

// httpServ will listen http requests at localhost:55590 and serve / for a static json response
func httpServ(quite bool) {
	gin.SetMode(gin.ReleaseMode)
	if quite {
		gin.DefaultWriter = io.Discard
	}
	// 启动gin框架，采用默认配置
	router := gin.Default()

	// 编写匿名的handler函数
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "hello,world",
		})
	})
	router.Run("localhost:55590")
}

// httpServ will listen https requests at localhost:55590 and serve / for a static json response, with cert ./server.pem and ./server.key
func httpsServ(quite bool) error {
	gin.SetMode(gin.ReleaseMode)
	if quite {
		gin.DefaultWriter = io.Discard
	}
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.String(200, "test for 【%s】", "https")
	})
	r.Use(tlsHandler(55590))

	return r.RunTLS("localhost:"+strconv.Itoa(55590), "./server.pem", "./server.key")
}

// tlsHandler returns a gin.HandlerFunc to handle HTTPS requests
func tlsHandler(port int) gin.HandlerFunc {
	return func(c *gin.Context) {
		secureMiddleware := secure.New(secure.Options{
			SSLRedirect: true,
			SSLHost:     ":" + strconv.Itoa(port),
		})
		err := secureMiddleware.Process(c.Writer, c.Request)

		// If there was an error, do not continue.
		if err != nil {
			return
		}

		c.Next()
	}
}

// tcpEcho reads up to 64KB from a connection, and then writes them back
func tcpEcho() {
	conn, err := net.Dial("tcp4", "127.0.0.1:55590")
	//log.Println("connected with groxy server from ", conn.LocalAddr().String())
	if err != nil {
		panic(err)
	}

	for true {
		read := make([]byte, 64*1024)
		//conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Read(read)
		if err != nil {
			return
		}
		_, err = conn.Write([]byte("echoing"))
		if err != nil {
			return
		}
	}
}

// getCertInfo returns cert object from a path to cert file
func getCertInfo(path string) pkix.Name {
	// Load the certificate file
	certBytes, err := os.ReadFile(path)
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

// tlsServ reads up to 64Bytes from a TLS connection, and then writes them back, with a prefix
func tlsServ() {
	cert, err := tls.LoadX509KeyPair("server.pem", "server.key")
	certInfo := getCertInfo("server.pem")
	if err != nil {
		panic(err)
	}

	log.Printf("Simple TLS server started with cert containing\n%v\n", certInfo)

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp4", ":55590", config)
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

// handleConn is the handler func of tlsServ
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

// main is the entry point of simple_serv.go
func main() {
	mode := flag.String("mode", "tls", "the mode for simpleServ (tls or tcp)")
	quite := flag.Bool("quite", true, "Quite Mode")
	flag.Parse()

	if *mode == "tls" {
		log.Println("started tls server")
		tlsServ()
	}
	if *mode == "tcp" {
		log.Println("started tcp listen server")
		tcpServ()
	}
	if *mode == "tcpEcho" {
		log.Println("started tcp echo server")
		for true {
			tcpEcho()
		}
	}
	if *mode == "http" {
		log.Println("started HTTP listen server")
		httpServ(*quite)
	}
	if *mode == "https" {
		log.Println("started HTTPS listen server")
		err := httpsServ(*quite)
		if err != nil {
			log.Println(err)
			return
		}
	}
}
