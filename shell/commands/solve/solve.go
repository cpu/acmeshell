package solve

import (
	"crypto"
	"encoding/base64"
	"flag"
	"fmt"
	"net/http"
	"strings"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "solve",
			Aliases:  []string{"solveChallenge"},
			Help:     "Complete an ACME challenge",
			LongHelp: `TODO(@cpu): Write this!`,
		},
		nil,
		solveHandler,
		nil)
}

type solveOptions struct {
	printKeyAuthorization bool
	printToken            bool
	orderIndex            int
	identifier            string
	challType             string
}

func solveHandler(c *ishell.Context, args []string) {
	opts := solveOptions{}
	solveFlags := flag.NewFlagSet("solve", flag.ContinueOnError)
	solveFlags.BoolVar(&opts.printKeyAuthorization, "printKeyAuth", false, "Print calculated key authorization")
	solveFlags.BoolVar(&opts.printToken, "printToken", false, "Print challenge token")
	solveFlags.StringVar(&opts.challType, "challengeType", "", "Challenge type to solve")
	solveFlags.StringVar(&opts.identifier, "identifier", "", "Authorization identifier to solve for")
	solveFlags.IntVar(&opts.orderIndex, "order", -1, "index of existing order")

	leftovers, err := commands.ParseFlagSetArgs(args, solveFlags)
	if err != nil {
		return
	}

	client := commands.GetClient(c)
	challSrv := commands.GetChallSrv(c)

	var targetURL string
	if len(leftovers) > 0 {
		templateText := strings.Join(leftovers, " ")
		targetURL, err = commands.ClientTemplate(client, templateText)
		if err != nil {
			c.Printf("solve: error templating order URL: %v\n", err)
			return
		}
	} else {
		targetURL, err = commands.FindOrderURL(c, nil, opts.orderIndex)
		if err != nil {
			c.Printf("solve: error getting order URL: %v\n", err)
			return
		}
		targetURL, err = commands.FindAuthzURL(c, targetURL, opts.identifier)
		if err != nil {
			c.Printf("solve: error getting authz URL: %v\n", err)
			return
		}
	}

	authz := &resources.Authorization{
		ID: targetURL,
	}
	err = client.UpdateAuthz(authz)
	if err != nil {
		c.Printf("solve: error getting authorization object from %q: %v\n", targetURL, err)
		return
	}

	var chall *resources.Challenge
	if opts.challType != "" {
		for _, c := range authz.Challenges {
			if c.Type == opts.challType {
				chall = &c
				break
			}
		}
		if chall == nil {
			c.Printf("solve: authz %q has no %q type challenge\n",
				authz.ID, opts.challType)
			return
		}
	} else {
		var err error
		chall, err = commands.PickChall(c, authz)
		if err != nil {
			c.Printf("solve: error picking challenge: %v\n", err)
			return
		}
	}

	token := chall.Token
	if opts.printToken {
		c.Printf("challenge token:\n%s\n", token)
	}

	jwk := jose.JSONWebKey{
		Key: client.ActiveAccount.PrivateKey.Public(),
	}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		c.Printf("solve: error computing account JWK thumbprint: %s", err.Error())
		return
	}
	encodedThumbprint := base64.RawURLEncoding.EncodeToString(thumbprint)
	keyAuth := fmt.Sprintf("%s.%s", token, encodedThumbprint)
	if opts.printKeyAuthorization {
		c.Printf("key authorization:\n%s\n", keyAuth)
	}

	switch strings.ToUpper(chall.Type) {
	case "HTTP-01":
		challSrv.AddHTTPOneChallenge(token, keyAuth)
	case "DNS-01":
		challSrv.AddDNSOneChallenge(authz.Identifier.Value, keyAuth)
	case "TLS-ALPN-01":
		challSrv.AddTLSALPNChallenge(authz.Identifier.Value, keyAuth)
	default:
		c.Printf("challenge %q has unknown type: %q\n", chall.URL, chall.Type)
		return
	}
	c.Printf("Challenge response ready\n")

	signResult, err := client.Sign(chall.URL, []byte("{}"), nil)
	if err != nil {
		c.Printf("solve: failed to sign challenge POST body: %s\n", err.Error())
		return
	}

	resp, err := client.PostURL(chall.URL, signResult.SerializedJWS)
	if err != nil {
		c.Printf("solve: failed to POST challenge %q: %v\n", chall.URL, err)
		return
	}
	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("solve: failed to POST %q challenge. Status code: %d\n", chall.URL, respOb.StatusCode)
		c.Printf("solve: response body: %s\n", resp.RespBody)
		return
	}
	c.Printf("solve: %q challenge for identifier %q (%q) started\n", chall.Type, authz.Identifier.Value, chall.URL)
}
