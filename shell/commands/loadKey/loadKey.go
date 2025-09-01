package loadKey

import (
	"encoding/pem"
	"flag"
	"os"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/keys"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "loadKey",
			Aliases:  []string{"loadPrivateKey"},
			Help:     "Load an existing PEM ECDSA private key from disk",
			LongHelp: `TODO(@cpu): Write this!`,
			Func:     loadKeyHandler,
		},
		nil)
}

type loadKeyOptions struct {
	id string
}

func loadKeyHandler(c *ishell.Context) {
	opts := loadKeyOptions{}
	loadKeyFlags := flag.NewFlagSet("loadKey", flag.ContinueOnError)
	loadKeyFlags.StringVar(&opts.id, "id", "", "ID for the key")

	leftovers, err := commands.ParseFlagSetArgs(c.Args, loadKeyFlags)
	if err != nil {
		return
	}

	if len(leftovers) < 1 {
		c.Printf("loadKey: you must specify a PEM filepath to load from\n")
		return
	}

	argument := strings.TrimSpace(leftovers[0])
	client := commands.GetClient(c)

	if opts.id == "" {
		opts.id = argument
	}

	if _, found := client.Keys[opts.id]; found {
		c.Printf("loadKey: there is already a key loaded under ID %q\n", opts.id)
		return
	}

	pemBytes, err := os.ReadFile(argument)
	if err != nil {
		c.Printf("loadKey: error reading key PEM from file %q: %s", argument, err.Error())
		return
	}

	block, _ := pem.Decode(pemBytes)

	var keyType string
	switch t := strings.ToUpper(block.Type); t {
	case "EC PRIVATE KEY":
		keyType = "ecdsa"
	case "RSA PRIVATE KEY":
		keyType = "rsa"
	default:
		c.Printf("loadKey: unknown PEM block type %q\n", t)
		return
	}

	signer, err := keys.UnmarshalSigner(block.Bytes, keyType)
	if err != nil {
		c.Printf("loadKey: error loading private key from PEM bytes in %q: %v", argument, err)
		return
	}

	client.Keys[opts.id] = signer
	c.Printf("loadKey: restored key from %q to ID %q\n", argument, opts.id)
}
