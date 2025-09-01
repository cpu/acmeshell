package newKey

import (
	"flag"
	"os"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/keys"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "newKey",
			Aliases:  []string{"newPrivateKey"},
			Help:     "Create a new private key for use with newAccount/CSR/sign",
			LongHelp: `TODO(@cpu): Write this!`,
			Func:     newKeyHandler,
		},
		nil)
}

type newKeyOptions struct {
	keyID    string
	printPEM bool
	printJWK bool
	pemPath  string
	keyType  string
}

func newKeyHandler(c *ishell.Context) {
	opts := newKeyOptions{}
	newKeyFlags := flag.NewFlagSet("newKey", flag.ContinueOnError)
	newKeyFlags.StringVar(&opts.keyID, "id", "", "ID for the new key")
	newKeyFlags.BoolVar(&opts.printPEM, "pem", false, "Print PEM output")
	newKeyFlags.BoolVar(&opts.printJWK, "jwk", true, "Print JWK output")
	newKeyFlags.StringVar(&opts.pemPath, "path", "", "Path to write PEM private key to")
	newKeyFlags.StringVar(&opts.keyType, "type", "ecdsa", "Type of key to generate rsa or ecdsa")

	if _, err := commands.ParseFlagSetArgs(c.Args, newKeyFlags); err != nil {
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

	if opts.keyType != "ecdsa" && opts.keyType != "rsa" {
		c.Printf("newKey: -type must be rsa or ecdsa not %q\n", opts.keyType)
		return
	}

	client := commands.GetClient(c)

	if _, found := client.Keys[opts.keyID]; found {
		c.Printf("newKey: there is already a key with ID %q\n", opts.keyID)
		return
	}

	randKey, err := keys.NewSigner(opts.keyType)
	if err != nil {
		c.Printf("newKey: error generating new key: %s\n", err.Error())
		return
	}

	client.Keys[opts.keyID] = randKey

	keyPem, err := keys.SignerToPEM(randKey)
	if err != nil {
		c.Printf("newKey: error marshaling key to PEM: %v\n", err)
		return
	}

	if opts.pemPath != "" {
		err := os.WriteFile(opts.pemPath, []byte(keyPem), os.ModePerm)
		if err != nil {
			c.Printf("newKey: error writing pem to %q: %s\n", opts.pemPath, err.Error())
			return
		}
		c.Printf("PEM encoded private key saved to %q\n", opts.pemPath)
	}

	if opts.printPEM {
		c.Printf("PEM:\n%s\n", keyPem)
	}

	if opts.printJWK {
		c.Printf("JWK:\n%s\n", keys.JWKJSON(randKey))
	}
}
