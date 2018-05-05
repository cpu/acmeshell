package shell

import (
	"flag"
	"strings"
	"sync"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme"
	"github.com/cpu/acmeshell/cmd"
)

type getCmd struct {
	once *sync.Once
	cmd  *ishell.Cmd
}

type getOptions struct {
	acme.HTTPOptions
}

var get getCmd = getCmd{
	once: new(sync.Once),
	cmd: &ishell.Cmd{
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
}

func (g getCmd) New(client *acme.Client) *ishell.Cmd {
	// Get the directory from the client to use when constructing shell commands
	dirMap, err := client.Directory()
	cmd.FailOnError(err, "Unable to get ACME server directory")

	// If this was the first time New was called with a directory, set up the
	// completer. We can't create a static completer in the getCmd initializer
	// because the directory isn't known. Unfortunately the ishell.Completer
	// function signature doesn't allow passing the ishell.State or directory as
	// a parameter either so we have to use this `sync.Once` approach and
	// a constructor.
	get.once.Do(func() {
		get.cmd.Completer = directoryKeyCompleter(dirMap, []string{"directory"})
	})
	return get.cmd
}

func getURL(opts getOptions, targetURL string, c *ishell.Context) {
	client := getClient(c)

	respCtx := client.GetURL(targetURL, &opts.HTTPOptions)
	if respCtx.Err != nil {
		c.Printf("get: error getting URL: %s\n", respCtx.Err)
		return
	}
}

func getHandler(c *ishell.Context) {
	opts := getOptions{}
	getFlags := flag.NewFlagSet("get", flag.ContinueOnError)
	// Set up flags for the get flagset
	getFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	getFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	getFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")

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
	client := getClient(c)

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
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("get: warning: templating error: %s\n", err.Error())
			// Fall back to using the raw argument untemplated
			rendered = argument
		}
		// Use the templated result as the argument
		argument = rendered

		// Otherwise treat the argument as a raw URL and make sure it is valid-ish
		if !okURL(argument) {
			c.Printf("get: illegal url argument %q\n", argument)
			return
		}
		// If it is, use the raw argument as the target URL
		targetURL = argument
	}

	getURL(opts, targetURL, c)
}
