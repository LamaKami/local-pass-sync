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

	loggingSetup(cfg.LoggingPath)

	switch os.Args[1] {
	case "server":
		server.Serving(cfg)
	case "compareFiles":
		client.HandlingPatchRequest(cfg)
	case "getFile":
		client.HandlingGetRequest(cfg)
	case "replaceFile":
		client.HandlingPutRequest(cfg)
	case "pubKey":
		privateKey, _ := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path, cfg.Ed25519private.Password)
		if err := k.PrintPublicKey(privateKey); err != nil{
			fmt.Println("While extracting the public from the private key the following error occurred: ", err)
		}
	case "help":
		fmt.Println("Possible actions: \ncompareFiles\ngetFile\nreplaceFile")
	default:
		fmt.Println("No such options")
	}
}

func loggingSetup(loggingPath string){
	if loggingPath == ""{
		return
	}

	file, err := os.OpenFile(loggingPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(file)
}