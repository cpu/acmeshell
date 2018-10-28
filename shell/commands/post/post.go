// Package post implements an ACMEShell command for POSTing requests to an ACME
// server.
package post

import (
	"encoding/json"
	"flag"
	"strings"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/shell/commands"
)

type postOptions struct {
	postBody     string
	templateBody bool
	sign         bool
}

var (
	opts = postOptions{}
)

const (
	longHelp = `
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
	`
)

func init() {
	registerPostCommand()
}

func registerPostCommand() {
	postFlags := flag.NewFlagSet("post", flag.ContinueOnError)
	postFlags.StringVar(&opts.postBody, "body", "", "HTTP POST request body")
	postFlags.BoolVar(&opts.templateBody, "templateBody", true, "Template HTTP POST body")
	postFlags.BoolVar(&opts.sign, "sign", true, "Sign body with active account key")

	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "post",
			Aliases:  []string{"postURL"},
			Help:     "Send an HTTP POST to a ACME endpoint or a URL",
			LongHelp: longHelp,
		},
		commands.DirectoryAutocompleter,
		postHandler,
		postFlags)
}

func postHandler(c *ishell.Context, leftovers []string) {
	if len(leftovers) < 1 {
		c.Printf("post: you must specify an endpoint or a URL\n")
		return
	}

	argument := strings.TrimSpace(leftovers[0])
	client := commands.GetClient(c)

	var targetURL string

	if endpointURL, ok := client.GetEndpointURL(argument); ok {
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

	postURL(c, targetURL)
}

func postURL(c *ishell.Context, targetURL string) {
	client := commands.GetClient(c)
	account := client.ActiveAccount

	postBody := []byte(opts.postBody)
	if opts.sign {
		if account == nil {
			c.Printf("post: no active ACME account to authenticate POST requests\n")
			return
		}
		signResult, err := client.Sign(targetURL, postBody, nil)
		if err != nil {
			c.Printf("post: error signing POST request body: %s\n", err)
			return
		}
		postBody = signResult.SerializedJWS
	}

	resp, err := client.PostURL(targetURL, postBody)
	if err != nil {
		c.Printf("post: error POSTing signed request body to URL: %v\n", err)
		return
	}
	c.Printf("%s\n", resp.RespBody)
}
