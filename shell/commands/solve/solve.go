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
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/shell/commands"
)

type solveCmd struct {
	commands.BaseCmd
}

type solveOptions struct {
	printKeyAuthorization bool
	printToken            bool
	challType             string
}

var SolveCommand = solveCmd{
	commands.BaseCmd{
		Cmd: &ishell.Cmd{
			Name:     "solve",
			Aliases:  []string{"solveChallenge"},
			Func:     solveHandler,
			Help:     "Complete an ACME challenge",
			LongHelp: `TODO(@cpu): Write this!`,
		},
	},
}

func (s solveCmd) Setup(client *acmeclient.Client) (*ishell.Cmd, error) {
	return SolveCommand.Cmd, nil
}

func solveHandler(c *ishell.Context) {
	opts := solveOptions{}
	solveFlags := flag.NewFlagSet("solve", flag.ContinueOnError)
	solveFlags.BoolVar(&opts.printKeyAuthorization, "printKeyAuth", false, "Print calculated key authorization")
	solveFlags.BoolVar(&opts.printToken, "printToken", false, "Print challenge token")
	solveFlags.StringVar(&opts.challType, "challengeType", "", "Challenge type to solve")

	err := solveFlags.Parse(c.Args)
	if err != nil && err != flag.ErrHelp {
		c.Printf("solve: error parsing input flags: %s\n", err.Error())
		return
	} else if err == flag.ErrHelp {
		return
	}

	client := commands.GetClient(c)
	challSrv := commands.GetChallSrv(c)

	var authzURL string
	if len(solveFlags.Args()) == 0 {
		order, err := commands.PickOrder(c)
		if err != nil {
			c.Printf("solve: error picking order to solve: %s\n", err.Error())
			return
		}
		authz, err := commands.PickAuthz(c, order)
		if err != nil {
			c.Printf("solve: error picking authz to solve: %s\n", err.Error())
			return
		}
		authzURL = authz.ID
	} else {
		templateText := strings.Join(solveFlags.Args(), " ")
		rendered, err := commands.EvalTemplate(
			templateText,
			commands.TemplateCtx{
				Client: client,
				Acct:   client.ActiveAccount,
			})
		if err != nil {
			c.Printf("solve: authz URL templating error: %s\n", err.Error())
			return
		}
		authzURL = rendered
	}

	authz := &resources.Authorization{
		ID: authzURL,
	}
	err = client.UpdateAuthz(authz)
	if err != nil {
		c.Printf("solve: error getting authz: %s\n", err.Error())
		return
	}

	var chall *resources.Challenge
	if opts.challType == "" {
		chall, err = commands.PickChall(c, authz)
		if err != nil {
			c.Printf("solve: error picking challenge: %s", err.Error())
			return
		}
	} else {
		for _, c := range authz.Challenges {
			if opts.challType == c.Type {
				chall = &c
				break
			}
		}
		if chall == nil {
			c.Printf("solve: authz %q has no %q challenge type\n", authz.ID, opts.challType)
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
