package main

import (
	"go-test/socks5"
	"log"
	"net"
)

func main() {
	serv, err := net.Listen("tcp4", ":48620")
	if err != nil {
		log.Fatal(err)
	}
	for {
		client, err := serv.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		go socks5.ConnectAndAuthSocks5Client(client)
	}

}
