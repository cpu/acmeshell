package get

import (
	"flag"
	"strings"
	"sync"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/shell/commands"
)

type getCmd struct {
	commands.BaseCmd
}

var GetCommand = getCmd{
	BaseCmd: commands.BaseCmd{
		Once: new(sync.Once),
		Cmd: &ishell.Cmd{
			Name:    "get",
			Aliases: []string{"getURL"},
			Func:    getHandler,
			Help:    "Send an HTTP GET to a ACME endpoint or a URL",
			LongHelp: `
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
	`,
		},
	},
}

func (g getCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	// Get the directory from the client to use when constructing shell commands
	dirMap, err := client.Directory()
	if err != nil {
		return nil, err
	}

	// If this was the first time New was called with a directory, set up the
	// completer. We can't create a static completer in the getCmd initializer
	// because the directory isn't known. Unfortunately the ishell.Completer
	// function signature doesn't allow passing the ishell.State or directory as
	// a parameter either so we have to use this `sync.Once` approach and
	// a constructor.
	GetCommand.Once.Do(func() {
		GetCommand.Cmd.Completer = commands.DirectoryKeyCompleter(dirMap, []string{"directory"})
	})
	return GetCommand.Cmd, nil
}

func getURL(targetURL string, c *ishell.Context) {
	client := commands.GetClient(c)

	_, err := client.GetURL(targetURL, &acmeclient.HTTPOptions{
		PrintResponse: true,
	})
	if err != nil {
		c.Printf("get: error getting URL: %v\n", err)
		return
	}
}

func getHandler(c *ishell.Context) {
	getFlags := flag.NewFlagSet("get", flag.ContinueOnError)
	// Set up flags for the get flagset

	err := getFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("get: error parsing input flags: %s", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if getFlags.NArg() < 1 {
		c.Printf("get: you must specify an endpoint or a URL\n")
		return
	}

	argument := strings.TrimSpace(getFlags.Arg(0))
	client := commands.GetClient(c)

	var targetURL string

	if argument == "directory" {
		// If the argument is "directory", use the directory URL as the target
		targetURL = client.DirectoryURL.String()
	} else if endpointURL, ok := client.GetEndpointURL(argument); ok {
		// If the argument is an endpoint, find its URL
		targetURL = endpointURL
	} else {
		templateText := strings.Join(getFlags.Args(), " ")

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

	getURL(targetURL, c)
}
