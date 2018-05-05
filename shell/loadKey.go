package shell

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
)

type loadKeyCmd struct {
	cmd *ishell.Cmd
}

type loadKeyOptions struct {
	id string
}

var loadKey loadKeyCmd = loadKeyCmd{
	cmd: &ishell.Cmd{
		Name:     "loadKey",
		Aliases:  []string{"loadPrivateKey"},
		Func:     loadKeyHandler,
		Help:     "Load an existing PEM ECDSA private key from disk",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (lk loadKeyCmd) New(client *acme.Client) *ishell.Cmd {
	return loadKey.cmd
}

func loadKeyHandler(c *ishell.Context) {
	opts := loadKeyOptions{}
	loadKeyFlags := flag.NewFlagSet("loadKey", flag.ContinueOnError)
	loadKeyFlags.StringVar(&opts.id, "id", "", "ID for the key")

	err := loadKeyFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("loadKeys: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if loadKeyFlags.NArg() != 1 {
		c.Printf("loadKey: you must specify a PEM filepath to load from\n")
		return
	}

	argument := strings.TrimSpace(loadKeyFlags.Arg(0))
	client := getClient(c)

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
