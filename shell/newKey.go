package shell

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"os"

	jose "gopkg.in/square/go-jose.v2"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type newKeyCmd struct {
	cmd *ishell.Cmd
}

type newKeyOptions struct {
	keyID    string
	printPEM bool
	printJWK bool
	pemPath  string
}

var newKey newKeyCmd = newKeyCmd{
	cmd: &ishell.Cmd{
		Name:     "newKey",
		Aliases:  []string{"newPrivateKey"},
		Func:     newKeyHandler,
		Help:     "Create a new private key for use with newAccount/CSR/sign",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (nk newKeyCmd) New(client *acme.Client) *ishell.Cmd {
	return newKey.cmd
}

func newKeyHandler(c *ishell.Context) {
	opts := newKeyOptions{}
	newKeyFlags := flag.NewFlagSet("newKey", flag.ContinueOnError)
	newKeyFlags.StringVar(&opts.keyID, "id", "", "ID for the new key")
	newKeyFlags.BoolVar(&opts.printPEM, "pem", false, "Print PEM output")
	newKeyFlags.BoolVar(&opts.printJWK, "jwk", true, "Print JWK output")
	newKeyFlags.StringVar(&opts.pemPath, "path", "", "Path to write PEM private key to")

	err := newKeyFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("newKey: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if opts.keyID == "" {
		c.Printf("newKey: -id must not be empty\n")
		return
	}

	if !opts.printPEM && !opts.printJWK {
		c.Printf("newKey: one of -pem or -jwk must be true\n")
		return
	}

	client := getClient(c)

	if _, found := client.Keys[opts.keyID]; found {
		c.Printf("newKey: there is already a key with ID %q\n", opts.keyID)
		return
	}

	randKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		c.Printf("newKey: error generating new key: %s\n", err.Error())
		return
	}

	client.Keys[opts.keyID] = randKey
	keyBytes, err := x509.MarshalECPrivateKey(randKey)
	if err != nil {
		c.Printf("newKey: failed to marshal EC key bytes: %s\n", err.Error())
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	if opts.pemPath != "" {
		err := ioutil.WriteFile(opts.pemPath, pemBytes, os.ModePerm)
		if err != nil {
			c.Printf("newKey: error writing pem to %q: %s\n", opts.pemPath, err.Error())
			return
		}
		c.Printf("PEM encoded private key saved to %q\n", opts.pemPath)
	}

	if opts.printPEM {
		c.Printf("PEM:\n%s\n", string(pemBytes))
	}

	if opts.printJWK {
		jwk := jose.JSONWebKey{
			Key:       randKey.Public(),
			Algorithm: "ECDSA",
		}
		jwkJSON, err := json.Marshal(&jwk)
		if err != nil {
			c.Printf("newKey: failed to marshal JWK: %s\n", err.Error())
			return
		}
		c.Printf("JWK:\n%s\n", string(jwkJSON))
	}
}
