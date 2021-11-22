package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/tobischo/gokeepasslib"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	"log"
	"net/http"
	"regexp"
	"sync"
)

var (
	createUserRe = regexp.MustCompile(`^/compare[/]*$`)
	cfg c.Config
	mut sync.Mutex
)

type userHandler struct {
	store *authorizedPublicKeys
}

type authorizedPublicKeys struct {
	pk map [string] ed25519.PublicKey
}

type Payload struct {
	Key string `json:"key"`
	File string `json:"file"`
	Signature string `json:"signature"`
	Message string `json:"message"`
}

// Serving saves the config as global variable
func Serving(cf c.Config){
	cfg = cf
	handleRequest()
}

func handleRequest(){
	userH := &userHandler{
		store: &authorizedPublicKeys{
			pk: k.LoadAuthorizedKeys(cfg.Server.AuthorizedKeysPath),
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/compare",userH)
	mux.Handle("/compare/",userH)
	err := http.ListenAndServeTLS(":"+cfg.Server.Port, cfg.SslCertificate.SelfSignedCertificate, cfg.SslCertificate.Key, mux)
	if err != nil {
		log.Fatal(err)
	}
}

// ServeHTTP chooses the correct function for the called path
func (h *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// if two requests arrive at the same time, the server processes only the first one and waits
	// until it is done with the request to process the next one
	mut.Lock()
	defer mut.Unlock()

	switch {
	case r.Method == http.MethodPost && createUserRe.MatchString(r.URL.Path):
		if err := h.Compare(w, r); err != nil{
			log.Println("The following error occurred while calling the compare endpoint: ", err)
		}
		return
	default:
		notFound(w)
		return
	}
}

// Compare handles the request if the client wants to update there file on the server/localhost
func (h *userHandler) Compare(w http.ResponseWriter, r *http.Request) error{
	// encodes json payload
	var p Payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		internalServerError(w)
		return err
	}

	// checks if the public is in the authorized keys and gets ed25519.PublicKey from the map if it is there
	publicKey, ok := h.store.pk[p.Key]
	if !ok {
		payload := createResponse("", nil, "", "You are not authorized!")
		err := sendResponseToClient(w, payload, 401)
		return err
	}

	// Verify ed25519 message and signature
	clientFile, err, verified := decodeFileAndVerify(w, p.File, p.Signature, publicKey)
	if err != nil{
		return err
	}
	if !verified {
		return nil
	}

	clientDb, serverDb, err := unlockDatabases(clientFile, getServerDb())

	if !compareDatabases(clientDb, serverDb){
		return closeFilesAndSendResponse(w, clientDb, serverDb)
	}

	err = createNewKeepassFile(w, clientDb, serverDb)

	return err
}

// checks if the signature matches the file for the public key which the client has sent,
// creates a 401 response if it couldn't verify
func decodeFileAndVerify(w http.ResponseWriter, file string, signature string, publicKey ed25519.PublicKey) ([]byte, error, bool){
	decodedFile, err := base64.StdEncoding.DecodeString(file)
	if err != nil{
		return nil, err, false
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil{
		return nil, err, false
	}

	isCorrectVerified := ed25519.Verify(publicKey, decodedFile, decodedSignature)

	if !isCorrectVerified {
		payload := createResponse("", nil, "", "The message could not be verified.\n " +
			"Maybe you used the wrong private key or the given public key is not your key.")
		err := sendResponseToClient(w, payload, 401)
		return nil, err, isCorrectVerified
	}

	return decodedFile, nil, isCorrectVerified
}

// unlocks the client and server database and returns the pointer for both
func unlockDatabases(clientFile []byte, serverFile []byte) (*gokeepasslib.Database, *gokeepasslib.Database, error){
	clientDb, err := unlockDatabase(clientFile, cfg.ClientKeepass.Password)
	if err != nil{
		return nil, nil, err
	}

	serverDb, err := unlockDatabase(serverFile, cfg.ServerKeepass.Password)
	return clientDb, serverDb, err
}

// if the client entries are same or older than the server entries, we just send the server file back to the client
func closeFilesAndSendResponse(w http.ResponseWriter, clientDb *gokeepasslib.Database, serverDb *gokeepasslib.Database)error{
	LockDatabase(clientDb)
	LockDatabase(serverDb)
	payload := createResponse("", make([]byte, 0), "", "Success, but no need to change files")
	return sendResponseToClient(w, payload, 200)
}

// if some client entries are newer than the server entries, we create a new file and send it back to the client
func createNewKeepassFile(w http.ResponseWriter, clientDb *gokeepasslib.Database, serverDb *gokeepasslib.Database) error{
	LockDatabase(clientDb)
	if err := saveAndLockDatabase(cfg.ServerKeepass.Path, serverDb); err != nil{
		return err
	}

	serverFile, err := ioutil.ReadFile(cfg.ServerKeepass.Path)
	if err != nil{
		return err
	}

	payload := createResponse("", serverFile, "", "File was successfully modified by the server")
	err = sendResponseToClient(w, payload, 200)
	return err
}

// creates a response body which can used for sendResponseToClient
func createResponse(key string, serverFile []byte, sig string, message string)[]byte{
	payload := Payload{
		Key: key,
		File: base64.StdEncoding.EncodeToString(serverFile),
		Signature: sig,
		Message: message,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}
	return payloadBytes
}

// sends a response back with given status and body payload
func sendResponseToClient(w http.ResponseWriter, payload []byte, status int) error{
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		return err
	}
	return nil
}

// returns the byte representation from the keepass file on the server
func getServerDb() []byte{
	file, err := ioutil.ReadFile(cfg.ServerKeepass.Path)
	if err != nil{
		log.Fatal(err)
	}
	return file
}

func internalServerError(w http.ResponseWriter) {
	payload := createResponse("", nil, "", "internal server error")
	if err := sendResponseToClient(w, payload, 500); err != nil{
		log.Println(err)
	}
}

// response when the path is not valid
func notFound(w http.ResponseWriter) {
	payload := createResponse("", nil, "", "endpoint not found")
	if err := sendResponseToClient(w, payload, 404); err != nil{
		log.Println(err)
	}
}