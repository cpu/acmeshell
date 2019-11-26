package jwsDecode

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "jwsDecode",
			Aliases:  []string{"jws"},
			Help:     "Decode a JWS and its raw Base64URL encoded fields",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		jwsDecodeHandler,
		nil)
}

type jwsDecodeOptions struct {
	data string
}

func jwsDecodeHandler(c *ishell.Context, args []string) {
	opts := jwsDecodeOptions{}
	jwsDecodeFlags := flag.NewFlagSet("jwsDecode", flag.ContinueOnError)

	if _, err := commands.ParseFlagSetArgs(args, jwsDecodeFlags); err != nil {
		return
	}

	var input string
	if opts.data == "" {
		input = readData(c)
	} else {
		input = opts.data
	}

	var jws struct {
		Payload   string
		Protected string
		Signature string
	}
	err := json.Unmarshal([]byte(input), &jws)
	if err != nil {
		c.Printf("error unmarshaling input JWS: %q\n", err)
		return
	}

	decodedPayload, err := decode(jws.Payload, false)
	if err != nil {
		c.Printf("error decoding input JWS payload field %q: %q\n", jws.Payload, err)
		return
	}

	decodedProtected, err := decode(jws.Protected, false)
	if err != nil {
		c.Printf("error decoding input JWS protected field %q: %q\n", jws.Protected, err)
		return
	}

	decodedSignature, err := decode(jws.Signature, true)
	if err != nil {
		c.Printf("error decoding input JWS signature field %q: %q\n", jws.Signature, err)
		return
	}

	c.Printf("Payload: %s\n", decodedPayload)
	c.Printf("Protected: %s\n", decodedProtected)
	c.Printf("Signature: %s\n", decodedSignature)
}

func readData(c *ishell.Context) string {
	c.SetPrompt(commands.BasePrompt + "JWS > ")
	defer c.SetPrompt(commands.BasePrompt)
	terminator := "."
	c.Printf("Input JWS to decode. "+
		" End by sending '%s'\n", terminator)
	return strings.TrimSuffix(c.ReadMultiLines(terminator), terminator)
}

func decode(data string, hex bool) (string, error) {
	result, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	resultString := string(result)

	if hex {
		var buff strings.Builder
		for {
			if len(result) == 0 {
				break
			}
			b := result[0]
			fmt.Fprintf(&buff, "0x%X ", b)
			result = result[1:]
		}
		resultString = buff.String()
	}
	return resultString, nil
}
