package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
)

func verifyMessage(w http.ResponseWriter, message string, signature string, publicKey ed25519.PublicKey) (error, bool){

	decodedSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil{
		return err, false
	}

	isCorrectVerified := ed25519.Verify(publicKey, []byte(message), decodedSignature)

	if !isCorrectVerified {
		payload := createResponse("", nil, "", "The message could not be verified.\n " +
			"Maybe you used the wrong private key or the given public key is not your key.")
		err := sendResponseToClient(w, payload, 401)
		return err, isCorrectVerified
	}

	return nil, isCorrectVerified
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
		payload := createResponse("", nil, "", "The file could not be verified.\n " +
			"Maybe you used the wrong private key or the given public key is not your key.")
		err := sendResponseToClient(w, payload, 401)
		return nil, err, isCorrectVerified
	}

	return decodedFile, nil, isCorrectVerified
}