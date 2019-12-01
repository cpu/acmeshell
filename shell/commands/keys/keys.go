package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/keys"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "viewKey",
			Aliases:  []string{"keys", "viewKeys"},
			Help:     "View available private keys",
			LongHelp: `TODO(@cpu): Write keys longhelp`,
			Func:     keysHandler,
		},
		nil)
}

type viewKeyOptions struct {
	pem           bool
	jwk           bool
	hexthumbprint bool
	b64thumbprint bool
	pemPath       string
}

func keysHandler(c *ishell.Context) {
	opts := viewKeyOptions{}
	viewKeyFlags := flag.NewFlagSet("viewKey", flag.ContinueOnError)
	viewKeyFlags.BoolVar(&opts.pem, "pem", false, "Display private key in PEM format")
	viewKeyFlags.BoolVar(&opts.jwk, "jwk", true, "Display public key in JWK format")
	viewKeyFlags.BoolVar(&opts.b64thumbprint, "b64thumbprint", true, "Display JWK public key thumbprint in base64url encoded form")
	viewKeyFlags.BoolVar(&opts.hexthumbprint, "hexthumbprint", false, "Display JWK public key thumbprint in hex encoded form")
	viewKeyFlags.StringVar(&opts.pemPath, "path", "", "Path to write PEM private key to")

	leftovers, err := commands.ParseFlagSetArgs(c.Args, viewKeyFlags)
	if err != nil {
		return
	}

	client := commands.GetClient(c)

	if len(client.Keys) == 0 {
		c.Printf("Client has no keys created\n")
		return
	}

	var key crypto.Signer
	if len(leftovers) == 0 {
		var keysList []string
		for k := range client.Keys {
			keysList = append(keysList, k)
		}
		sort.Strings(keysList)

		choiceList := make([]string, len(client.Keys))
		for i, keyID := range keysList {
			active := " "
			if keyID == client.ActiveAccountID() {
				active = "*"
			}
			choiceList[i] = fmt.Sprintf("%s%s", active, keyID)
		}

		choice := c.MultiChoice(choiceList, "Which key would you like to view? ")
		key = client.Keys[keysList[choice]]
	} else {
		templateText := strings.Join(leftovers, " ")
		rendered, err := commands.ClientTemplate(client, templateText)
		if err != nil {
			c.Printf("viewKey: key ID templating error: %s\n", err.Error())
			return
		}
		// Use the templated result as the argument
		if k, found := client.Keys[rendered]; found {
			key = k
		}
		if key == nil {
			c.Printf("viewKey: no key known to shell with id %q\n", rendered)
			return
		}
	}

	var keyBytes []byte
	var keyHeader string
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err = x509.MarshalECPrivateKey(k)
		keyHeader = "EC PRIVATE KEY"
	case *rsa.PrivateKey:
		keyBytes = x509.MarshalPKCS1PrivateKey(k)
		keyHeader = "RSA PRIVATE KEY"
	default:
		err = fmt.Errorf("unknown key type: %T", k)
	}
	if err != nil {
		c.Printf("viewKey: failed to marshal key bytes: %s\n", err.Error())
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  keyHeader,
		Bytes: keyBytes,
	})

	if opts.pem {
		c.Printf("PEM:\n%s\n", string(pemBytes))
	}

	if opts.pemPath != "" {
		err := ioutil.WriteFile(opts.pemPath, pemBytes, os.ModePerm)
		if err != nil {
			c.Printf("viewKey: error writing pem to %q: %s\n", opts.pemPath, err.Error())
			return
		}
		c.Printf("PEM encoded private key saved to %q\n", opts.pemPath)
	}

	if opts.jwk {
		c.Printf("JWK:\n%s\n", keys.JWKJSON(key))
	}

	if opts.hexthumbprint || opts.b64thumbprint {
		thumbBytes := keys.JWKThumbprintBytes(key)
		thumbprint := keys.JWKThumbprint(key)

		if opts.hexthumbprint {
			c.Printf("Hex Thumbprint:\n%#x\n", thumbBytes)
		}
		if opts.b64thumbprint {
			c.Printf("b64url Thumbprint:\n%s\n", thumbprint)
		}
	}
}
