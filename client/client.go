package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	s "local-pass-sync/server"
	"log"
	"net/http"
	"os"
	"strings"
)

// creates a request with the given config, method, path and the body payload
func createRequest(cfg c.Config, body *bytes.Reader, method string, apiPath string) (*http.Request, error){
	req, err := http.NewRequest(method, "https://" + cfg.Server.Domain + ":" + cfg.Server.Port + apiPath, body)
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

// creates a client for a https request
func createTlsClient(cfg c.Config) *http.Client{
	cert, err := os.ReadFile(cfg.SslCertificate.SelfSignedCertificate)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		log.Fatalf("unable to parse cert from %s", cfg.SslCertificate.SelfSignedCertificate)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	return client
}

// Writes the response data to disk if a file was send
// The Boolean indicated if there is a new file
func handleResponse(cfg c.Config, resp *http.Response) (error, bool){
	var returnPayload s.Payload

	if strings.Contains(resp.Status, "404") || strings.Contains(resp.Status, "500"){
		log.Fatal(resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&returnPayload); err != nil {
		return err, false
	}

	if !strings.Contains(resp.Status, "200"){
		log.Fatal(resp.Status, returnPayload.Message)
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

	outFile, err := os.Create(cfg.Keepass.ClientPath)
	if err != nil{
		return err, false
	}

	_, err = outFile.Write(decodedFile)
	if err != nil {
		return err, false
	}
	return outFile.Close(), true
}

// creates a byte reader from the kdbx file and the ed25519 keys
// the returned reader can be used as the body parameter for a http request
func createFileRequestBody(cfg c.Config) (*bytes.Reader, error) {
	f, err := ioutil.ReadFile(cfg.Keepass.ClientPath)
	if err != nil {
		return nil, err
	}
	privateKey, pubKey := k.GetPublicAndPrivateKey(cfg.Ed25519private.Path, cfg.Ed25519private.Password)

	payload := s.Payload{
		Key:       k.PublicKeyToString(pubKey),
		File:      base64.StdEncoding.EncodeToString(f),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, f)),
	}

	payloadBytes, err := json.Marshal(payload)

	return bytes.NewReader(payloadBytes), err

}