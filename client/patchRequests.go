package client

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	s "local-pass-sync/server"
	"log"
)

// HandlingPostRequest uses the config to create the request and also handles the server response
func HandlingPostRequest(cfg c.Config){
	body, err := createPostRequestBody(cfg)
	if err != nil{
		log.Fatal("While creating the request body with the kdbx file and the keys," +
			" the following error occurred: ", err)
	}

	req, err := createRequest(cfg, body, "POST", "/keepass")
	if err != nil{
		log.Fatal("While creating the post request, the following error occurred: ", err)
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

	if err, changed := handleResponse(cfg, resp); err != nil{
		log.Fatal("While handling the server response, the following error occurred: ", err)
	} else if !changed{
		return
	}

	log.Println("File was successfully changed on the client")
}

// creates a byte reader from the kdbx file and the ed25519 keys
// the returned reader can be used as the body parameter for a http request
func createPostRequestBody(cfg c.Config) (*bytes.Reader, error){
	f, err := ioutil.ReadFile(cfg.Keepass.ClientPath)
	if err != nil{
		return nil, err
	}
	privateKey, pubKey := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path, cfg.Ed25519private.Password)

	payload := s.Payload{
		Key: k.PublicKeyToString(pubKey),
		File: base64.StdEncoding.EncodeToString(f),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, f)),
	}

	payloadBytes, err := json.Marshal(payload)

	return bytes.NewReader(payloadBytes), err
}
