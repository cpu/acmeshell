package loadKey

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "loadKey",
			Aliases:  []string{"loadPrivateKey"},
			Help:     "Load an existing PEM ECDSA private key from disk",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		loadKeyHandler,
		nil)
}

type loadKeyOptions struct {
	id string
}

func loadKeyHandler(c *ishell.Context, args []string) {
	opts := loadKeyOptions{}
	loadKeyFlags := flag.NewFlagSet("loadKey", flag.ContinueOnError)
	loadKeyFlags.StringVar(&opts.id, "id", "", "ID for the key")

	leftovers, err := commands.ParseFlagSetArgs(args, loadKeyFlags)
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

	pemBytes, err := ioutil.ReadFile(argument)
	if err != nil {
		c.Printf("loadKey: error reading key PEM from file %q: %s", argument, err.Error())
		return
	}

	block, _ := pem.Decode(pemBytes)
	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		c.Printf("loadKey: error decoding EC private key from PEM bytes in %q: %s", argument, err.Error())
		return
	}

	client.Keys[opts.id] = privKey
	c.Printf("loadKey: restored key from %q to ID %q\n", argument, opts.id)
}
