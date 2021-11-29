package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	s "local-pass-sync/server"
	"log"
)

// HandlingGetRequest uses the config to create the request and also handles the server response
func HandlingGetRequest(cfg c.Config){
	body, err := createGetRequestBody(cfg)
	if err != nil{
		log.Fatal("While creating the request body with the kdbx file and the keys," +
			" the following error occurred: ", err)
	}

	req, err := createRequest(cfg, body, "GET", "/keepass")
	if err != nil{
		log.Fatal("While creating the get request, the following error occurred: ", err)
	}

	resp, err := createTlsClient(cfg).Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("While closing the request body, the following error occurred: ",err)
		}
	}(resp.Body)

	err, changed := handleResponse(cfg, resp)
	if err != nil{
		log.Fatal(err)
	}

	if !changed {
		log.Println("There was no file on the server.")
	}
}

func createGetRequestBody(cfg c.Config) (*bytes.Reader, error){
	privateKey, pubKey := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path, cfg.Ed25519private.Password)
	message := "get file from server"

	payload := s.Payload{
		Key: k.PublicKeyToString(pubKey),
		File: "",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message))),
		Message: message,
	}

	payloadBytes, err := json.Marshal(payload)

	return bytes.NewReader(payloadBytes), err
}