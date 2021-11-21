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
	if err := c.LoadConfig(&cfg); err != nil{
		log.Fatal("Error while loading Config: ", err)
	}

	switch os.Args[1] {
	case "server":
		server.Serving(cfg)
	case "client":
		client.HandlingRequest(cfg)
	case "pubKey":
		privateKey, _ := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path)
		if err := k.PrintPublicKey(privateKey); err != nil{
			fmt.Println("While extracting the public from the private key the following error occurred: ", err)
		}
	case "help":
		fmt.Println("Possible actions: \nserver\nclient\npubKey")
	default:
		fmt.Println("No such options")
	}
}