// Package resources provides types for representing and interacting with ACME
// protocol resources.
package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
)

// Account holds information related to a single ACME Account resource. If the
// account has an empty ID it has not yet been created server-side with the ACME
// server using the client.CreateAccount function.
//
// The ID field holds the server assigned Account ID that is assigned at the
// time of account creation and used as the JWS KeyID for authenticating ACME
// requests with the Account's registered keypair.
//
// The Contact field is either nil or a slice of one or more email addresses
// to be used as the ACME Account's "mailto://" Contact addresses.
//
// The PrivateKey field is a pointer to a private key used for the ACME
// account's keypair. The public component is computed from this private key
// automatically.
//
// The Orders field is either nil or a slice of one or more Order resource URLs.
// These URLs correspond to Orders that the Account created with the ACME
// server.
type Account struct {
	// The server assigned Account ID. This is used for the JWS KeyID when
	// authenticating ACME requests using the Account's registered keypair.
	ID string
	// If not nil, a slice of one or more email addresses to be used as the ACME
	// Account's "mailto://" Contact addresses.
	Contact []string
	// A pointer to a private key used for the ACME account's
	// keypair.
	//
	// TODO(@cpu): This should be using the right interface instead of restricting
	// usage to ECDSA instances.
	PrivateKey *ecdsa.PrivateKey
	// If not nil, a slice of URLs for Order resources the Account created with
	// the ACME server.
	Orders []string
}

// String returns the Account's ID or an empty string if it has not been created
// with the ACME server.
func (a Account) String() string {
	return a.ID
}

// NewAccount creates an ACME account in-memory. *Important:* the
// created Account is *not* registered with the ACME server until
// it is explicitly "created" server-side using a Client instance's
// CreateAccount function.
//
// the emails argument is a slice of zero or more email addresses that should be
// used as the Account's Contact information.
//
// the privKey argument is a pointer to a private key that should be used for
// the Account keypair. It will be used to create JWS for requests when the
// Account is a Client's ActiveAccount. If the privKey argument is nil a new
// randomly generated private key will be used for the Account key.
func NewAccount(emails []string, privKey *ecdsa.PrivateKey) (*Account, error) {
	var contacts []string
	if len(emails) > 0 {
		for _, e := range emails {
			if e == "" {
				continue
			}
			contacts = append(contacts, fmt.Sprintf("mailto:%s", e))
		}
	}

	if privKey == nil {
		randKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privKey = randKey
	}

	return &Account{
		Contact:    contacts,
		PrivateKey: privKey,
	}, nil
}

// SaveAccount persists the given Account object (which must not be nil) to the
// given file path. If any errors occur serializing the account it will be
// returned.
func SaveAccount(path string, account *Account) error {
	if account == nil {
		return fmt.Errorf("account must not be nil")
	}
	// serialize the account
	frozenBytes, err := account.save()
	if err != nil {
		return err
	}
	// write the serialized data to the provided filepath
	return ioutil.WriteFile(path, frozenBytes, os.ModePerm)
}

type rawAccount struct {
	ID         string
	Contact    []string
	PrivateKey []byte
}

func (acct *Account) save() ([]byte, error) {
	k, err := x509.MarshalECPrivateKey(acct.PrivateKey)
	if err != nil {
		return nil, err
	}

	rawAcct := rawAccount{
		ID:         acct.ID,
		Contact:    acct.Contact,
		PrivateKey: k,
	}
	frozenAcct, err := json.MarshalIndent(rawAcct, "", "  ")
	if err != nil {
		return nil, err
	}
	return frozenAcct, nil
}

// RestoreAccount loads a previously saved Account object from the given file
// path. This file should have been created using SaveAccount in a previous
// session. If any errors occur deserializing an Account from the data in the
// provided filepath a nil Account instance and a non-nil error will be
// returned.
func RestoreAccount(path string) (*Account, error) {
	acct := &Account{}
	frozenBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return acct, err
	}

	err = acct.restore(frozenBytes)
	return acct, err
}

func (acct *Account) restore(frozenAcct []byte) error {
	var rawAcct rawAccount

	err := json.Unmarshal(frozenAcct, &rawAcct)
	if err != nil {
		return err
	}

	privKey, err := x509.ParseECPrivateKey(rawAcct.PrivateKey)
	if err != nil {
		return err
	}

	acct.ID = rawAcct.ID
	acct.Contact = rawAcct.Contact
	acct.PrivateKey = privKey
	return nil
}
