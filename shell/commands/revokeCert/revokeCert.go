package revokeCert

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"net/http"
	"os"

	"github.com/abiosoft/ishell"
	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
	"github.com/cpu/acmeshell/net"
	"github.com/cpu/acmeshell/shell/commands"
)

func init() {
	commands.RegisterCommand(
		&ishell.Cmd{
			Name:     "revokeCert",
			Aliases:  []string{"revokeCertificate", "revoke"},
			Help:     "TODO: Describe the revokeCert command",
			LongHelp: "TODO: Describe the revokeCert command (long)",
			Func:     revokeCertHandler,
		},
		nil)
}

type revokeOptions struct {
	orderIndex int
	keyID      string
	certPEM    string
	reason     int
}

func revokeCertHandler(c *ishell.Context) {
	opts := revokeOptions{}
	revokeFlags := flag.NewFlagSet("revokeCert", flag.ContinueOnError)
	revokeFlags.IntVar(&opts.orderIndex, "order", -1, "index of order to revoke")
	revokeFlags.StringVar(&opts.keyID, "keyID", "", "Key ID to use for embedded JWK revocation")
	revokeFlags.StringVar(&opts.certPEM, "certPEM", "", "Path to PEM Certificate file to revoke")
	// TODO(@cpu): Consider parsing string names for codes from
	// https://tools.ietf.org/html/rfc5280#section-5.3.1
	revokeFlags.IntVar(&opts.reason, "reason", 1, "Revocation reason code, see https://tools.ietf.org/html/rfc5280#section-5.3.1")

	leftovers, err := commands.ParseFlagSetArgs(c.Args, revokeFlags)
	if err != nil {
		return
	}

	client := commands.GetClient(c)

	revokeURL, ok := client.GetEndpointURL("revokeCert")
	if !ok {
		c.Printf("revokeCert: no revokeCert endpoint in server's directory response\n")
		return
	}

	if opts.certPEM != "" && (len(leftovers) > 0 || opts.orderIndex != -1) {
		c.Printf("revokeCert: -certPEM is mutually exclusive with -orderIndex or a cert URL\n")
		return
	}

	var pemBytes []byte
	// TODO(@cpu): There should be a higher level GetCertificate function on the
	// client that this and the getCert command can share.
	if opts.certPEM == "" {
		orderURL, err := commands.FindOrderURL(c, leftovers, opts.orderIndex)
		if err != nil {
			c.Printf("revokeCert: error getting order URL: %v\n", err)
			return
		}

		order := &resources.Order{
			ID: orderURL,
		}
		err = client.UpdateOrder(order)
		if err != nil {
			c.Printf("revokeCert: error getting order: %s\n", err.Error())
			return
		}

		if order.Status != "valid" {
			c.Printf("revokeCert: order %q is status %q, not \"valid\"\n", order.ID, order.Status)
			return
		}

		if order.Certificate == "" {
			c.Printf("revokeCert: order %q has no Certificate URL\n", order.ID)
			return
		}

		var resp *net.NetResponse
		if client.PostAsGet {
			resp, err = client.PostAsGetURL(order.Certificate)
		} else {
			resp, err = client.GetURL(order.Certificate)
		}
		if err != nil {
			c.Printf("revokeCert: failed to GET order certificate URL %q : %v\n", order.Certificate, err)
			return
		}
		respOb := resp.Response
		if respOb.StatusCode != http.StatusOK {
			c.Printf("revokeCert: failed to GET order certificate URL %q . Status code: %d\n", order.Certificate, respOb.StatusCode)
			c.Printf("revokeCert: response body: %s\n", resp.RespBody)
			return
		}

		pemBytes = resp.RespBody
	} else {
		fileBytes, err := os.ReadFile(opts.certPEM)
		if err != nil {
			c.Printf("revokeCert: error reading -certPEM argument: %q\n", err)
			return
		}
		pemBytes = fileBytes
	}
	pemBlock, _ := pem.Decode(pemBytes)
	certBytes := pemBlock.Bytes

	revokeRequest := struct {
		Certificate string
		Reason      int
	}{
		Certificate: base64.RawURLEncoding.EncodeToString(certBytes),
		Reason:      opts.reason,
	}
	revokeRequestJSON, _ := json.Marshal(&revokeRequest)

	signOpts := &acmeclient.SigningOptions{}

	if opts.keyID != "" {
		if key, found := client.Keys[opts.keyID]; found {
			// If there was a key ID specified then we want to embed that key as the JWK
			// authorizing the revocation request.
			signOpts.EmbedKey = true
			signOpts.Signer = key
		}
		if signOpts.Signer == nil {
			c.Printf("revokeCert: no key with ID %q exists in shell\n", opts.keyID)
			return
		}
	}

	signResult, err := client.Sign(revokeURL, revokeRequestJSON, signOpts)
	if err != nil {
		c.Printf("revokeCert: failed to sign revocation request: %v\n", err)
		return
	}

	c.Printf("POSTing %q to revoke certificate\n", revokeURL)
	resp, err := client.PostURL(revokeURL, signResult.SerializedJWS)
	if err != nil {
		c.Printf("revokeCert: POST request failed: %v\n", err)
		return
	}

	respOb := resp.Response
	if respOb.StatusCode != http.StatusOK {
		c.Printf("revokeCert: POST request failed. Status code: %d\n", respOb.StatusCode)
		return
	}

	c.Printf("Successfully revoked certificate\n")
}
