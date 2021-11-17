package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	c "local-pass-sync/config"
	k "local-pass-sync/key"
	"log"
	"net/http"
	"regexp"
	"sync"
)

var (
	listUserRe = regexp.MustCompile(`^\/compare[\/]*$`)
	createUserRe = regexp.MustCompile(`^\/compare[\/]*$`)
)

var cfg c.Config

func Serving(cf c.Config){
	cfg = cf
	handleRequest()
}

type userHandler struct {
	store *authorizedPublicKeys
}


type authorizedPublicKeys struct {
	pk map [string] ed25519.PublicKey
	*sync.RWMutex
}

func (h *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("content-type", "application/json")
	switch {
	case r.Method == http.MethodPost && createUserRe.MatchString(r.URL.Path):
		h.Create(w, r)
		return
	default:
		notFound(w)
		return
	}
}

func handleRequest(){
	userH := &userHandler{
		store: &authorizedPublicKeys{
			pk: k.LoadAuthorizedKeys(cfg.Server.AuthorizedKeysPath),
			RWMutex: &sync.RWMutex{},
		},
	}

	mux := http.NewServeMux()
	mux.Handle("/compare",userH)
	mux.Handle("/compare/",userH)
	http.ListenAndServe(":8081", mux)
}

type Payload struct {
	Key string `json:"key"`
	File string `json:"file"`
	Signature string `json:"signature"`
}

func (h *userHandler) Create(w http.ResponseWriter, r *http.Request) {
	var p Payload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		internalServerError(w)
		return
	}
	h.store.RLock()
	pub, ok := h.store.pk[p.Key]
	h.store.RUnlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("public key not found"))
		return
	}

	decodedFile, err := base64.StdEncoding.DecodeString(p.File)
	if err != nil{
		log.Fatal(err)
	}

	decodedSignature, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil{
		log.Fatal(err)
	}

	isCorrectVerified := ed25519.Verify(pub,decodedFile,decodedSignature)

	if !isCorrectVerified {
		//TODO correct error message
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	keepassFile, err := base64.StdEncoding.DecodeString(p.File)
	if err != nil{
		log.Fatal(err)
	}

	clientDb := unlockDatabase(keepassFile, cfg.ClientKeepass.Password)
	serverDb := unlockDatabase(getServerDb(), cfg.ServerKeepass.Password)

	compareDatabases(clientDb, serverDb)

	LockDatabase(clientDb)
	saveAndLockDatabase(cfg.ServerKeepass.Path,serverDb)

	serverFile, err := ioutil.ReadFile(cfg.ServerKeepass.Path)
	if err != nil{
		log.Fatal("Error while loading new file")
	}

	payload := Payload{
		Key: "Key",
		File: base64.StdEncoding.EncodeToString(serverFile),
		Signature: "sig",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Fatal(err)
	}

	if err != nil {
		internalServerError(w)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(payloadBytes)
}

func getServerDb() []byte{
	file, err := ioutil.ReadFile(cfg.ServerKeepass.Path)
	if err != nil{
		log.Fatal(err)
	}
	return file
}

func internalServerError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("internal server error"))
}

func notFound(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("not found"))
}