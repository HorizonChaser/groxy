package main

import (
	"go-test/client"
	"go-test/serv"
	"log"
	"os"
)

// main is the integrated entrance for groxy application, including both groxy server and client.
// NOTE: the server/client mode flag (-s/-c) MUST be set as the first arg passed to main,
// otherwise main couldn't recognize the proper mode due to limitations of the std flag library,
// which is used to parse the command line args
func main() {

	isClientMode := false
	isModeSet := false

	// let's see which role we gonna act as
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
		log.Println("Groxy cannot start because no mode has been set, or it couldn't recognize at least")
		log.Println("To begin with, you need to specify whether to work in client mode by -c or -client, ")
		log.Println("Or in server mode by -s or -server")
		log.Println("NOTE: this argument need to be placed as the FIRST argument when groxy is started.")
		os.Exit(-1)
	}

	if !isClientMode {
		serv.ServMain()
	} else {
		client.ClientMain()
	}
}
