package get

import (
	"fmt"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

var ()

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
	registerGetCommand()
}

func registerGetCommand() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "get",
			Aliases:  []string{"getURL"},
			Help:     "Send an HTTP GET to a ACME endpoint or a URL",
			LongHelp: longHelp,
		},
		commands.DirectoryAutocompleter,
		getHandler,
		nil)
}

func getHandler(c *ishell.Context, leftovers []string) {
	if len(leftovers) < 1 {
		c.Printf("get: you must specify an endpoint or a URL\n")
		return
	}

	argument := strings.TrimSpace(leftovers[0])
	client := commands.GetClient(c)

	var targetURL string

	if argument == "directory" {
		// If the argument is "directory", use the directory URL as the target
		targetURL = client.DirectoryURL.String()
	} else if endpointURL, ok := client.GetEndpointURL(argument); ok {
		// If the argument is an endpoint, find its URL
		targetURL = endpointURL
	} else {
		templateText := strings.Join(leftovers, " ")

		// Render the input as a template
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("get: warning: templating error: %s\n", err.Error())
			// Fall back to using the raw argument untemplated
			rendered = argument
		}
		// Use the templated result as the argument
		argument = rendered

		// Otherwise treat the argument as a raw URL and make sure it is valid-ish
		if !commands.OkURL(argument) {
			c.Printf("get: illegal url argument %q\n", argument)
			return
		}
		// If it is, use the raw argument as the target URL
		targetURL = argument
	}

	resp, err := client.GetURL(targetURL)
	if err != nil {
		c.Printf("get: error getting URL: %v\n", err)
		return
	}
	fmt.Printf("%s\n", resp.RespBody)
}
