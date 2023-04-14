package main

import (
	"go-test/client"
	"go-test/serv"
	"log"
	"os"
)

func main() {

	isClientMode := false
	isModeSet := false

	if os.Args[1] == "-s" || os.Args[1] == "-server" {
		isModeSet = true
		isClientMode = false
		os.Args = append(os.Args[0:1], os.Args[2:]...)
	} else if os.Args[1] == "-c" || os.Args[1] == "-client" {
		isModeSet = true
		isClientMode = true
		os.Args = append(os.Args[0:1], os.Args[2:]...)
	}

	if isModeSet == false {
		log.Println("Groxy cannot start because no mode has been set.")
		log.Println("To begin with, you need to specify whether to work in client mode by -c or -client, ")
		log.Println("Or in server mode by -s or -server")
		log.Println("Note that this argument need to be placed as the FIRST argument when groxy is started.")
		os.Exit(-1)
	}

	if !isClientMode {
		serv.ServMain()
	} else {
		client.ClientMain()
	}
}
