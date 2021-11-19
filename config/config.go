package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os/user"
	"path/filepath"
	"strings"
)

type Config struct {
	Ed25519private struct {
		Password string
		Path 	 string
	}
	Server struct {
		Port 			   string
		Domain			   string
		AuthorizedKeysPath string `yaml:"authorized_keys_path"`
	}
	ClientKeepass struct{
		Password	string
		Path 		string
	}`yaml:"client_keepass"`
	ServerKeepass struct{
		Password	string
		Path 		string
	}`yaml:"server_keepass"`
	SslCertificate struct{
		SelfSignedCertificate string `yaml:"self_signed_certificate"`
		Key		    		  string

	}`yaml:"ssl_certificate"`
}


func LoadConfig(cfg *Config){
	buf, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		log.Fatal(err)
	}

	err = yaml.Unmarshal(buf, cfg)
	if err != nil {
		log.Fatal(err)
	}

	addHomePath(cfg)
}

func addHomePath(cfg *Config) {
	usr, err := user.Current()
	if err != nil{
		fmt.Println("Can't access current path")
		return
	}
	dir := usr.HomeDir

	if strings.HasPrefix(cfg.Ed25519private.Path, "~/") {
		cfg.Ed25519private.Path = filepath.Join(dir, cfg.Ed25519private.Path[2:])
	}

	if strings.HasPrefix(cfg.Server.AuthorizedKeysPath, "~/") {
		cfg.Server.AuthorizedKeysPath = filepath.Join(dir, cfg.Server.AuthorizedKeysPath[2:])
	}

	if strings.HasPrefix(cfg.ClientKeepass.Path, "~/") {
		cfg.ClientKeepass.Path = filepath.Join(dir, cfg.ClientKeepass.Path[2:])
	}

	if strings.HasPrefix(cfg.ServerKeepass.Path, "~/") {
		cfg.ServerKeepass.Path = filepath.Join(dir, cfg.ServerKeepass.Path[2:])
	}
}