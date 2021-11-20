package config

import (
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"log"
	"os/user"
	"path/filepath"
	"strings"
)

// Config represents the implementation for the config.yaml file
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


func LoadConfig(cfg *Config) error{
	buf, err := ioutil.ReadFile("config.yaml")
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(buf, cfg); err != nil{
		return err
	}

	addHomePath(cfg)
	return nil
}

// converts the "~" symbol to the home directory
// Example: "~/.ssh" -> "/Users/userName/.ssh"
func addHomePath(cfg *Config) {
	usr, err := user.Current()
	if err != nil{
		log.Println("Can't access current path, if you are using the '~' symbol in the config the program might fail.")
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