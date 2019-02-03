package b64url

import (
	"encoding/base64"
	"errors"
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

type b64urlOptions struct {
	encode bool
	decode bool
	data   string
	hex    bool
}

func (opts b64urlOptions) validate() error {
	if opts.encode && opts.decode {
		return errors.New("both -encode and -decode can not be provided at once")
	}
	if !opts.encode && !opts.decode {
		return errors.New("One of -encode or -decode must be provided")
	}
	return nil
}

var (
	opts = b64urlOptions{}
)

func init() {
	registerB64URLCommand()
}

func registerB64URLCommand() {
	b64urlFlags := flag.NewFlagSet("b64url", flag.ContinueOnError)
	b64urlFlags.BoolVar(&opts.encode, "encode", false, "Encode the input string as a raw base64 URL encoded string")
	b64urlFlags.BoolVar(&opts.decode, "decode", false, "Decode the input string from base64 URL encoding")
	b64urlFlags.StringVar(&opts.data, "data", "", "Data to encode/decode")
	b64urlFlags.BoolVar(&opts.hex, "hex", false, "Output result in hex instead of as a string")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "b64url",
			Aliases:  []string{"base64url", "base64"},
			Help:     "Base64URL encode/decode utility",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		b64urlHandler,
		b64urlFlags)
}

func readData(c *ishell.Context) string {
	c.SetPrompt(commands.BasePrompt + "b64url data > ")
	defer c.SetPrompt(commands.BasePrompt)
	terminator := "."
	c.Printf("Input data to encode/decode. "+
		" End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func b64urlHandler(c *ishell.Context, leftovers []string) {
	defer func() {
		opts = b64urlOptions{}
	}()

	if err := opts.validate(); err != nil {
		c.Printf("Invalid options: %s\n", err)
		return
	}

	var input string
	if opts.data == "" {
		input = readData(c)
	} else {
		input = opts.data
	}

	var output []byte

	if opts.decode {
		result, err := base64.RawURLEncoding.DecodeString(input)
		if err != nil {
			c.Printf("Error decoding input: %v\n", err)
			return
		}
		output = result
	} else if opts.encode {
		result := base64.RawURLEncoding.EncodeToString([]byte(input))
		output = []byte(result)
	}

	if opts.hex {
		c.Printf("Result:\n")
		for {
			if len(output) == 0 {
				break
			}
			b := output[0]
			c.Printf("0x%X ", b)
			output = output[1:]
		}
		c.Printf("\n")
	} else {
		c.Printf("Result: \n%s\n", string(output))
	}
}
