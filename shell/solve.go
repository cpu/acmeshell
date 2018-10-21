package shell

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"sort"
	"strings"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

type solveOptions struct {
	printKeyAuthorization bool
	printToken            bool
	challType             string
}

type solveCmd struct {
	cmd *ishell.Cmd
}

var solve solveCmd = solveCmd{
	cmd: &ishell.Cmd{
		Name:     "solve",
		Aliases:  []string{"solveChallenge"},
		Func:     solveHandler,
		Help:     "Complete an ACME challenge",
		LongHelp: `TODO(@cpu): Write this!`,
	},
}

func (s solveCmd) New(client *acmeclient.Client) *ishell.Cmd {
	return solve.cmd
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

	client := getClient(c)
	challSrv := getChallSrv(c)

	var authzURL string
	if len(solveFlags.Args()) == 0 {
		order, err := pickOrder(c)
		if err != nil {
			c.Printf("solve: error picking order to solve: %s\n", err.Error())
			return
		}
		authz, err := pickAuthz(c, order)
		if err != nil {
			c.Printf("solve: error picking authz to solve: %s\n", err.Error())
			return
		}
		authzURL = authz.ID
	} else {
		templateText := strings.Join(solveFlags.Args(), " ")
		rendered, err := evalTemplate(templateText, tplCtx{
			client: client,
			acct:   client.ActiveAccount,
		})
		if err != nil {
			c.Printf("solve: authz URL templating error: %s\n", err.Error())
			return
		}
		authzURL = rendered
	}

	authz, err := getAuthzObject(client, authzURL, nil)
	if err != nil {
		c.Printf("solve: error getting authz: %s\n", err.Error())
		return
	}

	var chall *resources.Challenge
	if opts.challType == "" {
		chall, err = pickChall(c, authz)
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

	signedBody, err := client.ActiveAccount.Sign(chall.URL, []byte("{}"), resources.SignOptions{
		NonceSource:    client,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	})
	if err != nil {
		c.Printf("solve: failed to sign challenge POST body: %s\n", err.Error())
		return
	}

	postOpts := &acmeclient.HTTPOptions{
		PrintHeaders:  false,
		PrintStatus:   false,
		PrintResponse: false,
	}

	respCtx := client.PostURL(chall.URL, signedBody, postOpts)
	if respCtx.Err != nil {
		c.Printf("solve: failed to POST challenge %q: %s\n", chall.URL, respCtx.Err.Error())
		return
	}
	if respCtx.Resp.StatusCode != http.StatusOK {
		c.Printf("solve: failed to POST %q challenge. Status code: %d\n", chall.URL, respCtx.Resp.StatusCode)
		c.Printf("solve: response body: %s\n", respCtx.Body)
		return
	}
	c.Printf("solve: %q challenge for identifier %q (%q) started\n", chall.Type, authz.Identifier.Value, chall.URL)
}

func pickChall(c *ishell.Context, authz *resources.Authorization) (*resources.Challenge, error) {
	if len(authz.Challenges) == 0 {
		return nil, fmt.Errorf("authz %q has no challenges", authz.ID)
	}

	challengeList := make([]string, len(authz.Challenges))
	for i, chall := range authz.Challenges {
		challengeList[i] = chall.Type
	}
	choice := c.MultiChoice(challengeList, "Select a challenge type")
	return &authz.Challenges[choice], nil
}

func pickAuthz(c *ishell.Context, order *resources.Order) (*resources.Authorization, error) {
	client := getClient(c)

	identifiersToAuthz := make(map[string]*resources.Authorization)
	for _, authzURL := range order.Authorizations {
		authz, err := getAuthzObject(client, authzURL, nil)
		if err != nil {
			return nil, err
		}

		ident := authz.Identifier.Value
		if authz.Wildcard {
			ident = "*." + ident
		}
		identifiersToAuthz[ident] = authz
	}

	var keysList []string
	for ident := range identifiersToAuthz {
		keysList = append(keysList, ident)
	}
	sort.Strings(keysList)

	choice := c.MultiChoice(keysList, "Choose an authorization")
	authz := identifiersToAuthz[keysList[choice]]
	return authz, nil
}

func getAuthzObject(client *acmeclient.Client, authzURL string, opts *acmeclient.HTTPOptions) (*resources.Authorization, error) {
	var authz resources.Authorization

	if opts == nil {
		opts = &acmeclient.HTTPOptions{
			PrintHeaders:  false,
			PrintStatus:   false,
			PrintResponse: false,
		}
	}
	respCtx := client.GetURL(authzURL, opts)
	if respCtx.Err != nil {
		return nil, fmt.Errorf("error getting authz %q: %s", authzURL, respCtx.Err.Error())
	}

	err := json.Unmarshal(respCtx.Body, &authz)
	if err != nil {
		return nil, fmt.Errorf("error unmarshaling authz %q: %s", authzURL, err.Error())
	}

	authz.ID = authzURL
	return &authz, nil
}

func getChallengeObject(client *acmeclient.Client, challengeURL string, opts *acmeclient.HTTPOptions) (*resources.Challenge, error) {
	var chall resources.Challenge
	if opts == nil {
		opts = &acmeclient.HTTPOptions{
			PrintHeaders:  false,
			PrintStatus:   false,
			PrintResponse: false,
		}
	}
	respCtx := client.GetURL(challengeURL, opts)
	if respCtx.Err != nil {
		return nil, respCtx.Err
	}
	err := json.Unmarshal(respCtx.Body, &chall)
	if err != nil {
		return nil, err
	}
	chall.URL = challengeURL
	return &chall, nil
}
