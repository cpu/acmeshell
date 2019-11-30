package keyAuth

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"flag"
	"fmt"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
	jose "gopkg.in/square/go-jose.v2"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "keyAuth",
			Aliases:  []string{"keyAuthorization", "keyAuthz"},
			Help:     "TODO: Describe the keyAuth command",
			LongHelp: "TODO: Describe the keyAuth command (long)",
			Func:     keyAuthHandler,
		},
		nil)
}

type keyAuthOptions struct {
	orderIndex int
	identifier string
	challType  string
	token      string
	keyID      string
}

func keyAuthHandler(c *ishell.Context) {
	var opts keyAuthOptions
	keyAuthFlags := flag.NewFlagSet("keyAuth", flag.ContinueOnError)
	keyAuthFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")
	keyAuthFlags.StringVar(&opts.identifier, "identifier", "", "identifier of authorization")
	keyAuthFlags.StringVar(&opts.challType, "type", "", "challenge type to get")
	keyAuthFlags.StringVar(&opts.token, "token", "", "challenge token")
	keyAuthFlags.StringVar(&opts.keyID, "keyID", "", "Key ID of existing key to use instead of active account key")

	if _, err := commands.ParseFlagSetArgs(c.Args, keyAuthFlags); err != nil {
		return
	}

	client := commands.GetClient(c)

	if opts.token != "" && (opts.orderIndex != -1 || opts.identifier != "" || opts.challType != "") {
		c.Printf("keyAuth: -token can not be used with -order -identifier or -challType\n")
		return
	}

	var token string
	if opts.token == "" {
		targetURL, err := commands.FindOrderURL(c, nil, opts.orderIndex)
		if err != nil {
			c.Printf("keyAuth: error getting order URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
		if err != nil {
			c.Printf("keyAuth: error getting authz URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindChallengeURL(c, targetURL, opts.challType)
		if err != nil {
			c.Printf("keyAuth: error getting challenge URL: %v\n", err)
			return
		}
		chall := &resources.Challenge{
			URL: targetURL,
		}
		if err = client.UpdateChallenge(chall); err != nil {
			c.Printf("keyAuth: error getting authz: %s\n", err.Error())
			return
		}
		token = chall.Token
	} else {
		token = opts.token
	}

	if token == "" {
		c.Printf("keyAuth: selected challenge token was empty\n")
	}

	var k *ecdsa.PrivateKey
	var kID string
	if opts.keyID != "" {
		if key, found := client.Keys[opts.keyID]; found {
			k = key
			kID = opts.keyID
		} else {
			c.Printf("keyAuth: no key with ID %q exists in shell\n", opts.keyID)
			return
		}
	} else {
		kID = client.ActiveAccountID()
		if kID == "" {
			c.Printf("keyAuth: no active account and no -keyID provided\n")
			return
		}
		k = client.ActiveAccount.PrivateKey
	}

	jwk := jose.JSONWebKey{
		Key:       k.Public(),
		Algorithm: "ECDSA",
	}
	thumbprintBytes, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		c.Printf("keyAuth: failed to compute Thumbprint for key %q: %v\n", kID, err)
		return
	}

	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)
	fmt.Printf("%s.%s\n", token, thumbprint)
}
