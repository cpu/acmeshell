package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
	jose "gopkg.in/square/go-jose.v2"
)

type viewKeyCmd struct {
	commands.BaseCmd
}

type viewKeyOptions struct {
	pem        bool
	jwk        bool
	thumbprint bool
	pemPath    string
}

var KeysCommand = viewKeyCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "viewKey",
			Aliases:  []string{"keys", "viewKeys"},
			Func:     keysHandler,
			Help:     "View available private keys",
			LongHelp: `TODO`,
		},
	},
}

func (vk viewKeyCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return KeysCommand.Cmd, nil
}

func keysHandler(c *ishell.Context) {
	opts := viewKeyOptions{}
	viewKeyFlags := flag.NewFlagSet("viewKey", flag.ContinueOnError)
	viewKeyFlags.BoolVar(&opts.pem, "pem", false, "Display private key in PEM format")
	viewKeyFlags.BoolVar(&opts.jwk, "jwk", true, "Display public key in JWK format")
	viewKeyFlags.BoolVar(&opts.thumbprint, "thumbprint", true, "Display hex JWK public key thumbprint")
	viewKeyFlags.StringVar(&opts.pemPath, "path", "", "Path to write PEM private key to")

	err := viewKeyFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("viewKey: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)

	if len(client.Keys) == 0 {
		c.Printf("No keys\n")
		return
	}

	var key *ecdsa.PrivateKey
	if len(viewKeyFlags.Args()) == 0 {
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
		templateText := strings.Join(viewKeyFlags.Args(), " ")

		// Render the input as a template
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("viewKey: key ID templating error: %s\n", err.Error())
			return
		}
		// Use the templated result as the argument
		if k, found := client.Keys[rendered]; !found {
			c.Printf("viewKey: no key known to shell with id %q\n", rendered)
			return
		} else {
			key = k
		}
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		c.Printf("viewKey: failed to marshal EC key bytes: %s\n", err.Error())
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		Algorithm: "ECDSA",
	}

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
		jwkJSON, err := json.Marshal(&jwk)
		if err != nil {
			c.Printf("viewKey: failed to marshal JWK: %s\n", err.Error())
			return
		}
		c.Printf("JWK:\n%s\n", string(jwkJSON))
	}

	if opts.thumbprint {
		thumb, err := jwk.Thumbprint(crypto.SHA256)
		if err != nil {
			c.Printf("INVALID-THUMBPRINT")
		}
		c.Printf("Thumbprint:\n%#x\n", thumb)
	}
}
