package shell

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/cpu/acmeshell/acme"
)

type tplCtx struct {
	acct   *acme.Account
	client *acme.Client
}

func (ctx tplCtx) order(index int) (*acme.Order, error) {
	if ctx.acct == nil {
		return nil, fmt.Errorf("no active account")
	}
	if index < 0 {
		return nil, fmt.Errorf("index must be > 0")
	}
	if len(ctx.acct.Orders) == 0 {
		return nil, fmt.Errorf("active account has no orders")
	}
	if index >= len(ctx.acct.Orders) {
		return nil, fmt.Errorf("index out of bounds. must be < %d", len(ctx.acct.Orders))
	}
	return getOrderObject(ctx.client, ctx.acct.Orders[index], nil)
}

func (ctx tplCtx) authz(order *acme.Order, identifier string) (*acme.Authorization, error) {
	if order == nil {
		return nil, fmt.Errorf("nil order argument")
	}
	if len(order.Authorizations) == 0 {
		return nil, fmt.Errorf("order has no authorizations")
	}
	if ctx.client == nil {
		return nil, fmt.Errorf("nil client in context")
	}

	var match *acme.Authorization
	for _, authzURL := range order.Authorizations {
		respCtx := ctx.client.GetURL(authzURL, nil)
		if respCtx.Err != nil {
			return nil, respCtx.Err
		}

		var authz acme.Authorization
		err := json.Unmarshal(respCtx.Body, &authz)
		if err != nil {
			return nil, err
		}
		authz.ID = authzURL

		if authz.Identifier.Value == identifier {
			match = &authz
			break
		}
	}

	if match == nil {
		return nil, fmt.Errorf("order has no authz for identifier %q", identifier)
	}

	return match, nil
}

func (ctx tplCtx) challenge(authz *acme.Authorization, challType string) (*acme.Challenge, error) {
	if authz == nil {
		return nil, fmt.Errorf("nil authz argument")
	}
	if len(authz.Challenges) == 0 {
		return nil, fmt.Errorf("authz has no challenges")
	}
	if challType == "" {
		challType = "http-01"
	}

	var match *acme.Challenge
	for _, chall := range authz.Challenges {
		if chall.Type == challType {
			match = &chall
			break
		}
	}

	if match == nil {
		return nil, fmt.Errorf("authz has no challenge with type == %q", challType)
	}

	return match, nil
}

func (ctx tplCtx) csr(order *acme.Order, privateKey *ecdsa.PrivateKey) (string, error) {
	if order == nil {
		return "", fmt.Errorf("nil order argument")
	}
	if len(order.Identifiers) == 0 {
		return "", fmt.Errorf("order has no identifiers")
	}

	names := make([]string, len(order.Identifiers))
	for i, ident := range order.Identifiers {
		names[i] = ident.Value
	}

	template := x509.CertificateRequest{
		DNSNames: names,
	}

	if privateKey == nil {
		privateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(csrBytes), nil
}

func (ctx tplCtx) account() (*acme.Account, error) {
	if ctx.acct == nil {
		return nil, fmt.Errorf("no active account")
	}
	return ctx.acct, nil
}

func (ctx tplCtx) key(keyID string) (*ecdsa.PrivateKey, error) {
	if len(ctx.client.Keys) == 0 {
		return nil, fmt.Errorf("no private keys in shell")
	}

	if k, ok := ctx.client.Keys[keyID]; ok {
		return k, nil
	}

	return nil, fmt.Errorf("no private key with key ID %q in shell", keyID)
}

func evalTemplate(templateStr string, ctx tplCtx) (string, error) {
	funcMap := template.FuncMap{
		"order":         ctx.order,
		"account":       ctx.account,
		"acct":          ctx.account,
		"authz":         ctx.authz,
		"authorization": ctx.authz,
		"challenge":     ctx.challenge,
		"chal":          ctx.challenge,
		"key":           ctx.key,
		"privateKey":    ctx.key,
		"csr":           ctx.csr,
		"CSR":           ctx.csr,
	}

	tmpl, err := template.New("input template").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return "", err
	}

	var outputBuilder strings.Builder
	err = tmpl.Execute(&outputBuilder, ctx)
	if err != nil {
		return "", err
	}

	return outputBuilder.String(), nil
}
