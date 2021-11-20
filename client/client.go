package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	s "local-pass-sync/server"
	"log"
	"net/http"
	"os"
)

// HandlingRequest uses the config to create the request and also handles the server response
func HandlingRequest(cfg c.Config){
	body, err := createRequestBody(cfg)
	if err != nil{
		log.Fatal("While creating the request body with the kdbx file and the keys," +
			" the following error occurred: ", err)
	}

	req, err := createPostRequest(cfg, body)
	if err != nil{
		log.Fatal("While creating the post request, the following error occurred: ", err)
	}

	resp, err := createClient().Do(req)
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
func createRequestBody(cfg c.Config) (*bytes.Reader, error){
	f, err := ioutil.ReadFile(cfg.ClientKeepass.Path)
	if err != nil{
		return nil, err
	}
	privateKey, pubKey := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path)

	payload := s.Payload{
		Key: k.PublicKeyToString(pubKey),
		File: base64.StdEncoding.EncodeToString(f),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, f)),
	}

	payloadBytes, err := json.Marshal(payload)

	return bytes.NewReader(payloadBytes), err
}

// creates a post request with the given config and the body payload
func createPostRequest(cfg c.Config, body *bytes.Reader) (*http.Request, error){
	req, err := http.NewRequest("POST", "https://" + cfg.Server.Domain + ":" + cfg.Server.Port + "/compare", body)
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

// creates a client for a https request
func createClient() *http.Client{
	// TODO insecure this part has to be changed
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}

// Writes the response data to disk if the file has changed
// The Boolean indicated if the file was changed
func handleResponse(cfg c.Config, resp *http.Response) (error, bool){
	var returnPayload s.Payload
	if err := json.NewDecoder(resp.Body).Decode(&returnPayload); err != nil {
		log.Fatal(err)
	}

	log.Printf(returnPayload.Message)

	// Checks if there is a new file to write to disk
	if len(returnPayload.File) == 0{
		return nil, false
	}

	decodedFile, err := base64.StdEncoding.DecodeString(returnPayload.File)
	if err != nil{
		return err, false
	}

	outFile, err := os.Create(cfg.ClientKeepass.Path)
	if err != nil{
		return err, false
	}

	_, err = outFile.Write(decodedFile)
	if err != nil {
		return err, false
	}
	return outFile.Close(), true
}