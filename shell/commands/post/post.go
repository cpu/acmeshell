// Package post implements an ACMEShell command for POSTing requests to an ACME
// server.
package post

import (
	"encoding/json"
	"flag"
	"strings"
	"sync"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type postOptions struct {
	acmeclient.HTTPOptions
	resources.SignOptions
	postBody     string
	templateBody bool
	sign         bool
}

type postCmd struct {
	commands.BaseCmd
}

var PostCommand = postCmd{
	BaseCmd: commands.BaseCmd{
		Once: new(sync.Once),
		Cmd: &ishell.Cmd{
			Name:    "post",
			Aliases: []string{"postURL"},
			Func:    postHandler,
			Help:    "Send an HTTP POST to a ACME endpoint or a URL",
			LongHelp: `
	post [acme endpoint]:
		Send an HTTP POST request to the URL that is contained in the ACME server's
		directory object under the specified endpoint name. You will be prompted
		interactively for the POST body (unless specified).

		Examples:
			post newOrder
				Send an HTTP POST to the "newOrder" key from the ACME server's directory
				object. The POST body will be read from stdin interactively.

			post -body='{"identifiers":[{"type":"dns", "value":"localhost.com"}]}' newOrder
				Send an HTTP POST with the given JSON body to the "newOrder" key from
				the ACME server's directory object.

	post [url]:
		Send an HTTP POST request to the URL specified.

		Examples:
			post https://acme-staging-v02.api.letsencrypt.org/acme/newOrder
				Send an HTTP POST to the Let's Encrypt V2 API's newOrder URL.
	`,
		},
	},
}

func (c postCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
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
	PostCommand.Once.Do(func() {
		PostCommand.Cmd.Completer = commands.DirectoryKeyCompleter(dirMap, nil)
	})
	return PostCommand.Cmd, nil
}

func postURL(opts postOptions, targetURL string, c *ishell.Context) {
	client := commands.GetClient(c)
	account := client.ActiveAccount

	if account == nil {
		c.Printf("post: no active ACME account to authenticate POST requests\n")
		return
	}

	postBody := []byte(opts.postBody)
	if opts.sign {
		signedBody, err := account.Sign(targetURL, postBody, resources.SignOptions{
			NonceSource:    client,
			PrintJWS:       opts.PrintJWS,
			PrintJWSObject: opts.PrintJWSObject,
			PrintJSON:      opts.PrintJSON,
		})
		if err != nil {
			c.Printf("post: error signing POST request body: %s\n", err)
			return
		}
		postBody = signedBody
	}

	respCtx := client.PostURL(targetURL, postBody, &opts.HTTPOptions)
	if respCtx.Err != nil {
		c.Printf("post: error POSTing signed request body to URL: %s\n", respCtx.Err)
		return
	}
}

func postHandler(c *ishell.Context) {
	// Set up flags for the get flagset
	opts := postOptions{}
	postFlags := flag.NewFlagSet("post", flag.ContinueOnError)
	postFlags.BoolVar(&opts.PrintHeaders, "headers", false, "Print HTTP response headers")
	postFlags.BoolVar(&opts.PrintStatus, "status", true, "Print HTTP response status code")
	postFlags.BoolVar(&opts.PrintResponse, "response", true, "Print HTTP response body")
	postFlags.BoolVar(&opts.PrintJWS, "jwsBody", false, "Print JWS body before POSTing")
	postFlags.BoolVar(&opts.PrintJWSObject, "jwsObj", false, "Print JWS object before POSTing")
	postFlags.BoolVar(&opts.PrintJSON, "jsonBody", false, "Print JSON body before signing")
	postFlags.StringVar(&opts.postBody, "body", "", "HTTP POST request body")
	postFlags.BoolVar(&opts.templateBody, "templateBody", true, "Template HTTP POST body")
	postFlags.BoolVar(&opts.sign, "sign", true, "Sign body with active account key")
	err := postFlags.Parse(c.Args)

	if err != nil && err != flag.ErrHelp {
		c.Printf("post: error parsing input flags: %s", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	if postFlags.NArg() < 1 {
		c.Printf("post: you must specify an endpoint or a URL\n")
		return
	}

	argument := strings.TrimSpace(postFlags.Arg(0))
	client := commands.GetClient(c)

	var targetURL string

	if endpointURL, ok := client.GetEndpointURL(argument); ok {
		// If the argument is an endpoint, find its URL
		targetURL = endpointURL
	} else {
		templateText := strings.Join(postFlags.Args(), " ")

		// Render the input as a template
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("post: target URL templating error: %s\n", err.Error())
			return
		}
		// Use the templated result as the argument
		targetURL = rendered
	}

	// Check the URL and make sure it is valid-ish
	if !commands.OkURL(targetURL) {
		c.Printf("post: illegal url argument %q\n", targetURL)
		return
	}

	// If the -body flag was specified and after trimming it is a non-empty value
	// use the trimmed value as the post body
	if trimmedBody := strings.TrimSpace(opts.postBody); trimmedBody != "" {
		opts.postBody = trimmedBody
	} else {
		// Otherwise, read the POST body interactively
		inputJSON := commands.ReadJSON(c)
		if inputJSON == "" {
			c.Printf("post: no POST body provided\n")
			return
		}
		opts.postBody = inputJSON
	}

	if opts.templateBody {
		// Render the body input as a template
		rendered, err := commands.EvalTemplate(
			opts.postBody,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("post: warning: target URL templating error: %s\n", err.Error())
			return
		}
		opts.postBody = rendered
	}

	var testOb interface{}
	// Trick the Go compiler into thinking we're using testOb. We deliberately
	// aren't but Go is too smart for that and throws a build err.
	_ = testOb
	if err := json.Unmarshal([]byte(opts.postBody), &testOb); err != nil {
		c.Printf("post: POST body was not legal JSON: %s\n", err)
		return
	}

	c.Printf("POSTing: \n%s\n", string(opts.postBody))
	postURL(opts, targetURL, c)
}
