package sign

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

type signCmd struct {
	commands.BaseCmd
}

type signCmdOptions struct {
	embedKey bool
	data     []byte
	keyID    string
}

var SignCommand = signCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "sign",
			Func:     signHandler,
			Help:     "Sign JSON for a URL with the active account key (or a specified key) and a nonce",
			LongHelp: `TODO(@cpu): write this`,
		},
	},
}

func (s signCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return SignCommand.Cmd, nil
}

func signData(opts signCmdOptions, targetURL string, c *ishell.Context) {
	client := commands.GetClient(c)
	account := client.ActiveAccount

	if account == nil && opts.keyID == "" {
		c.Printf("sign: no active ACME account to sign data with\n")
		return
	}

	signOpts := &acmeclient.SigningOptions{
		EmbedKey: opts.embedKey,
	}

	if opts.keyID != "" {
		if key, found := client.Keys[opts.keyID]; !found {
			c.Printf("sign: no key with ID %q exists in shell\n", opts.keyID)
			return
		} else {
			signOpts.Key = key
			if !opts.embedKey {
				signOpts.KeyID = opts.keyID
			}
		}
	}

	signResult, err := client.Sign(targetURL, opts.data, signOpts)
	if err != nil {
		c.Printf("sign: error signing data: %s\n", err)
		return
	}

	c.Printf("sign: Result JWS: \n%s\n", signResult.SerializedJWS)
}

func signHandler(c *ishell.Context) {
	// Set up flags for the sign cmd flagset
	opts := signCmdOptions{}
	signFlags := flag.NewFlagSet("sign", flag.ContinueOnError)
	signFlags.BoolVar(&opts.embedKey, "embedKey", false, "Embed JWK in JWS instead of a Key ID Header")
	signFlags.StringVar(&opts.keyID, "keyID", "", "Key ID of existing key to use instead of active account key")
	dataString := signFlags.String("data", "", "Data to sign")
	noData := signFlags.Bool("noData", false, "Use an empty byteslice as the data to sign (e.g. POST-as-GET)")
	err := signFlags.Parse(c.Args)

	if err != nil && err != flag.ErrHelp {
		c.Printf("sign: error parsing input flags: %s", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if signFlags.NArg() != 1 {
		c.Printf("sign: you must specify a URL for the JWS header\n")
		return
	}

	url := strings.TrimSpace(signFlags.Arg(0))

	if url == "" {
		c.Printf("sign: you must specify a non-empty URL for the JWS header\n")
		return
	}

	// If the -data flag was specified and after trimming it is a non-empty value
	// use the trimmed value as the data
	if trimmedData := strings.TrimSpace(*dataString); trimmedData != "" {
		if *noData {
			c.Printf("sign: using -noData and providing a -data value are mutually exclusive\n")
			return
		}
		opts.data = []byte(trimmedData)
	} else if !*noData {
		// Otherwise, read the POST body interactively
		inputJSON := commands.ReadJSON(c)
		opts.data = []byte(inputJSON)
	} else if *noData {
		opts.data = []byte("")
	}

	signData(opts, url, c)
}
