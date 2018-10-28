package sign

import (
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

type signCmdOptions struct {
	embedKey   bool
	data       []byte
	noData     bool
	keyID      string
	dataString string
}

var (
	opts = signCmdOptions{}
)

func init() {
	registerSignCmd()
}

func registerSignCmd() {
	signFlags := flag.NewFlagSet("sign", flag.ContinueOnError)
	signFlags.BoolVar(&opts.embedKey, "embedKey", false, "Embed JWK in JWS instead of a Key ID Header")
	signFlags.StringVar(&opts.keyID, "keyID", "", "Key ID of existing key to use instead of active account key")
	signFlags.StringVar(&opts.dataString, "data", "", "Data to sign")
	signFlags.BoolVar(&opts.noData, "noData", false, "Use an empty byteslice as the data to sign (e.g. POST-as-GET)")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "sign",
			Help:     "Sign JSON for a URL with the active account key (or a specified key) and a nonce",
			LongHelp: `TODO(@cpu): write this`,
		},
		nil,
		signHandler,
		signFlags)
}

func signHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = signCmdOptions{}
	}()
	if len(leftovers) < 1 {
		c.Printf("sign: you must specify a URL for the JWS header\n")
		return
	}

	url := strings.TrimSpace(leftovers[0])

	if url == "" {
		c.Printf("sign: you must specify a non-empty URL for the JWS header\n")
		return
	}

	// If the -data flag was specified and after trimming it is a non-empty value
	// use the trimmed value as the data
	if trimmedData := strings.TrimSpace(opts.dataString); trimmedData != "" {
		if opts.noData {
			c.Printf("sign: using -noData and providing a -data value are mutually exclusive\n")
			return
		}
		opts.data = []byte(trimmedData)
	} else if !opts.noData {
		// Otherwise, read the POST body interactively
		inputJSON := commands.ReadJSON(c)
		opts.data = []byte(inputJSON)
	} else if opts.noData {
		opts.data = []byte("")
	}

	signData(c, url)
}

func signData(c *ishell.Context, targetURL string) {
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
		if key, found := client.Keys[opts.keyID]; found {
			signOpts.Key = key
			if !opts.embedKey {
				signOpts.KeyID = opts.keyID
			}
		}
		if signOpts.Key == nil {
			c.Printf("sign: no key with ID %q exists in shell\n", opts.keyID)
			return
		}
	}

	signResult, err := client.Sign(targetURL, opts.data, signOpts)
	if err != nil {
		c.Printf("sign: error signing data: %s\n", err)
		return
	}

	c.Printf("sign: Result JWS: \n%s\n", signResult.SerializedJWS)
}
