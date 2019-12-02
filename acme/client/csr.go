package client

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/cpu/acmeshell/acme/keys"
)

// PEMCSR is the PEM encoding of an x509 Certificate Signing Request (CSR)
type PEMCSR string

// B64CSR is the Base64URLSafe encoding of an x509 Certificate Signing Request (CSR)
type B64CSR string

// CSR produces a CertificateSigningRequest for the provided commonName and SAN
// names. The keyID will be used to look up a client Keys entry to sign the CSR.
// The CSR will use the public component of this key as the CSR public key. If
// no commonName is provided the first of the names will be used. CSR returns
// the PEM encoding of the CSR as well as the Base64URL encoding of the CSR.
func (c *Client) CSR(commonName string, names []string, keyID string) (B64CSR, PEMCSR, error) {
	if len(names) == 0 {
		return B64CSR(""), PEMCSR(""), fmt.Errorf("no names specified")
	}

	if commonName == "" {
		commonName = names[0]
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames: names,
	}

	var privateKey crypto.Signer
	if keyID != "" {
		if key, found := c.Keys[keyID]; found {
			privateKey = key
		}
		if privateKey == nil {
			return B64CSR(""), PEMCSR(""), fmt.Errorf("no existing key in shell for key ID %q", keyID)
		}
	} else {
		// save a new random key for the names
		privateKey, _ = keys.NewSigner("ecdsa")
		c.Keys[strings.Join(names, ",")] = privateKey
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return B64CSR(""), PEMCSR(""), err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrBytes,
	})

	return B64CSR(base64.RawURLEncoding.EncodeToString(csrBytes)),
		PEMCSR(pemBytes),
		nil
}
