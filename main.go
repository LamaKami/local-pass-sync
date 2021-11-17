package main

import (
	"fmt"
	"local-pass-sync/client"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	"local-pass-sync/server"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Not enough arguments!")
	}
	var cfg c.Config
	c.LoadConfig(&cfg)

	switch os.Args[1] {
	case "server":
		server.Serving(cfg)
	case "client":
		client.SendRequest(cfg)
	case "pubKey":
		privateKey, _ := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path)
		k.PrintPublicKey(privateKey)
	default:
		fmt.Println("No such options")
	}
}