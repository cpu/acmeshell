package get

import (
	"fmt"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

const (
	longHelp = `
	get directory:
	  Send an HTTP GET request to the ACME server's directory URL.

	get [acme endpoint]:
		Send an HTTP GET request to the URL that is contained in the ACME server's
		directory object under the specified endpoint name.

		Examples:
			get newNonce
				Send an HTTP GET to the "newNonce" key from the ACME server's directory
				object.

	get [url]:
		Send an HTTP GET request to the URL specified.

		Examples:
			get https://acme-staging-v02.api.letsencrypt.org/build
				Send an HTTP GET to the Let's Encrypt V2 API's build URL.
	`
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "get",
			Aliases:  []string{"getURL"},
			Help:     "Send an HTTP GET to a ACME endpoint or a URL",
			LongHelp: longHelp,
			Func:     getHandler,
		},
		commands.DirectoryAutocompleter)
}

func getHandler(c *ishell.Context) {
	client := commands.GetClient(c)

	targetURL, err := commands.FindURL(client, c.Args)
	if err != nil {
		c.Printf("get: error finding URL: %v\n", err)
		return
	}

	if !commands.OkURL(targetURL) {
		c.Printf("get: illegal url argument %q\n", targetURL)
		return
	}

	resp, err := client.GetURL(targetURL)
	if err != nil {
		c.Printf("get: error getting URL: %v\n", err)
		return
	}
	fmt.Printf("%s\n", resp.RespBody)
}
