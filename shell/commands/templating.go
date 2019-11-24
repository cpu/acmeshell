package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"

	acmeclient "github.com/cpu/acmeshell/acme/client"
	"github.com/cpu/acmeshell/acme/resources"
)

type TemplateCtx struct {
	Acct   *resources.Account
	Client *acmeclient.Client
}

func (ctx TemplateCtx) order(index int) (*resources.Order, error) {
	if ctx.Acct == nil {
		return nil, fmt.Errorf("no active account")
	}
	if index < 0 {
		return nil, fmt.Errorf("index must be > 0")
	}
	if len(ctx.Acct.Orders) == 0 {
		return nil, fmt.Errorf("active account has no orders")
	}
	if index >= len(ctx.Acct.Orders) {
		return nil, fmt.Errorf("index out of bounds. must be < %d", len(ctx.Acct.Orders))
	}
	order := &resources.Order{
		ID: ctx.Acct.Orders[index],
	}
	err := ctx.Client.UpdateOrder(order)
	return order, err
}

func (ctx TemplateCtx) authz(order *resources.Order, identifier string) (*resources.Authorization, error) {
	if order == nil {
		return nil, fmt.Errorf("nil order argument")
	}
	if len(order.Authorizations) == 0 {
		return nil, fmt.Errorf("order has no authorizations")
	}
	if ctx.Client == nil {
		return nil, fmt.Errorf("nil client in context")
	}

	var match *resources.Authorization
	for _, authzURL := range order.Authorizations {
		var authz = &resources.Authorization{
			ID: authzURL,
		}
		if err := ctx.Client.UpdateAuthz(authz); err != nil {
			return nil, err
		}

		if authz.Identifier.Value == identifier {
			match = authz
			break
		}
	}

	if match == nil {
		return nil, fmt.Errorf("order has no authz for identifier %q", identifier)
	}

	return match, nil
}

func (ctx TemplateCtx) challenge(authz *resources.Authorization, challType string) (*resources.Challenge, error) {
	if authz == nil {
		return nil, fmt.Errorf("nil authz argument")
	}
	if len(authz.Challenges) == 0 {
		return nil, fmt.Errorf("authz has no challenges")
	}
	if challType == "" {
		challType = "http-01"
	}

	var match *resources.Challenge
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

func (ctx TemplateCtx) csr(order *resources.Order, privateKey *ecdsa.PrivateKey) (string, error) {
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

func (ctx TemplateCtx) account() (*resources.Account, error) {
	if ctx.Acct == nil {
		return nil, fmt.Errorf("no active account")
	}
	return ctx.Acct, nil
}

func (ctx TemplateCtx) key(keyID string) (*ecdsa.PrivateKey, error) {
	if len(ctx.Client.Keys) == 0 {
		return nil, fmt.Errorf("no private keys in shell")
	}

	if k, ok := ctx.Client.Keys[keyID]; ok {
		return k, nil
	}

	return nil, fmt.Errorf("no private key with key ID %q in shell", keyID)
}

func EvalTemplate(templateStr string, ctx TemplateCtx) (string, error) {
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

func ClientTemplate(c *acmeclient.Client, input string) (string, error) {
	return EvalTemplate(
		input,
		TemplateCtx{
			Client: c,
			Acct:   c.ActiveAccount,
		})
}
