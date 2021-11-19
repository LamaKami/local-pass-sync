package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
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

	req, err := http.NewRequest("POST", "https://" + cfg.Server.Domain + ":" + cfg.Server.Port + "/compare", body)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	// TODO insecure this part has to be changed
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	var returnPayload s.Payload
	if err := json.NewDecoder(resp.Body).Decode(&returnPayload); err != nil {
		log.Fatal(err)
	}

	log.Printf(returnPayload.Message)

	// Overwriting old file
	if len(returnPayload.File) == 0{
		return
	}

	outFile, _ := os.Create(cfg.ClientKeepass.Path)

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