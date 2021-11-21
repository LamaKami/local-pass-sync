package key

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// LoadAuthorizedKeys reads the public keys from file and saves them in a map
func LoadAuthorizedKeys(path string) map[string]ed25519.PublicKey {
	authorizedKeyFile, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}

	defer func(authorizedKeyFile *os.File) {
		err := authorizedKeyFile.Close()
		if err != nil {
			log.Println(err)
		}
	}(authorizedKeyFile)

	reader := bufio.NewReader(authorizedKeyFile)
	keys := make(map[string]ed25519.PublicKey)

	for{
		line, _, err := reader.ReadLine()
		if err != nil{
			break
		}
		if bytes.Contains(line,[]byte("BEGIN PUBLIC KEY")){
			// if we detect the starting indicator we will call the following function which handles the extraction
			// until the ending indicator is detected and finally writes the key to the hashmap
			extractKey(line, reader, keys)
		}
	}
	return keys
}

// reads a file (authorized_keys) of public keys and converts them into a hashmap with the string public key as the identifier
// and the public key with the PublicKey type as value
func extractKey(line []byte, reader *bufio.Reader, keys map[string]ed25519.PublicKey) {
	var start, end int
	byteKey := append(line, byte(10)) // adding linebreak is needed for the later pem decode
	start = len(byteKey)
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			break
		}
		if bytes.Contains(line, []byte("END PUBLIC KEY")) {
			byteKey = append(byteKey, byte(10)) // adding linebreak
			end = len(byteKey) - 1
			byteKey = append(byteKey, line...)
			break
		}
		byteKey = append(byteKey, line...)
	}

	keys[string(byteKey[start:end])] = bytesToPublicKey(byteKey)
}

// converts a byte representation from a public key PEM Data in a public key type
func bytesToPublicKey(fileKey []byte) ed25519.PublicKey{
	block, rest := pem.Decode(fileKey)
	if block == nil{
		log.Fatal("Error while decode", rest)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil{
		log.Fatal("Error while parsing public key ", err)
	}

	pubKey, success := key.(ed25519.PublicKey)
	if success != true{
		log.Fatal("Error while assigning parsed key to ed25519 public key variable")
	}
	return pubKey
}

// GetPublicAndPrivateKey loads the keys from the file in the path
func GetPublicAndPrivateKey(path string) (ed25519.PrivateKey, ed25519.PublicKey){
	privateKeyFileRead, err := ioutil.ReadFile(path)
	if err != nil{
		log.Fatal("Error while reading file: ", path, "\n", err)
	}

	key, err := ssh.ParseRawPrivateKey(privateKeyFileRead)
	if err != nil{
		log.Fatal("Error while parsing private key: ", err)
	}
	privateKey, correctType := key.(*ed25519.PrivateKey)
	if correctType != true{
		log.Fatal("Input key is in the wrong format")
	}

	return *privateKey, privateKey.Public().(ed25519.PublicKey)
}

// PrintPublicKey prints the public ed25519 for given private key
// this printed format for the public key should be inserted in the authorized_keys file
func PrintPublicKey(privateKey ed25519.PrivateKey) error{
	x509EncodedPub, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return err
	}

	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	fmt.Println(string(pemEncodedPub))
	return nil
}

// PublicKeyToString returns string representation without the begin and end block from the public key
func PublicKeyToString(key ed25519.PublicKey) string{
	x509EncodedPub, _ := x509.MarshalPKIXPublicKey(key)

	pemEncodedPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub}))
	splitKey := strings.Split(pemEncodedPub, "\n")
	return splitKey[1]
}
