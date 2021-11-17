package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	s "local-pass-sync/server"
	"log"
	"net/http"
	"os"
)

func SendRequest(cfg c.Config){
	f, err := ioutil.ReadFile(cfg.ClientKeepass.Path)
	if err != nil{
		log.Fatal(err)
	}
	privateKey, pubKey := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path)

	payload := s.Payload{
		Key: k.PublicKeyToString(pubKey),
		File: base64.StdEncoding.EncodeToString(f),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, f)),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	body := bytes.NewReader(payloadBytes)

	req, err := http.NewRequest("POST", "http://" + cfg.Server.Domain + ":" + cfg.Server.Port + "/compare", body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// Overwriting old file
	outFile, _ := os.Create(cfg.ClientKeepass.Path)


	var returnPayload s.Payload
	if err := json.NewDecoder(resp.Body).Decode(&returnPayload); err != nil {
		log.Fatal(err)
	}

	decodedFile, err := base64.StdEncoding.DecodeString(returnPayload.File)
	if err != nil{
		log.Fatal(err)
	}

	_, err = outFile.Write(decodedFile)
	if err != nil {
		return 
	}

	defer resp.Body.Close()
}