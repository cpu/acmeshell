// Package resources provides types for representing and interacting with ACME
// protocol resources.
package resources

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cpu/acmeshell/acme/keys"
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
// The Signer field is a pointer to a private key used for the ACME
// account's keypair. The public component is computed from this private key
// automatically.
//
// The Orders field is either nil or a slice of one or more Order resource URLs.
// These URLs correspond to Orders that the Account created with the ACME
// server.
//
// For information about the Account resource see
// https://tools.ietf.org/html/rfc8555#section-7.1.2
type Account struct {
	// The server assigned Account ID. This is used for the JWS KeyID when
	// authenticating ACME requests using the Account's registered keypair.
	ID string `json:"id"`
	// If not nil, a slice of one or more email addresses to be used as the ACME
	// Account's "mailto://" Contact addresses.
	Contact []string `json:"contact"`
	// A signer to use to sign protocol messages and to access the ACME account's
	// public key
	Signer crypto.Signer
	// If not nil, a slice of URLs for Order resources the Account created with
	// the ACME server.
	Orders []string `json:"orders"`
	// The JSON path backing the account (if any)
	jsonPath string
}

// String returns the Account's ID or an empty string if it has not been created
// with the ACME server.
func (a Account) String() string {
	return a.ID
}

func (a Account) Path() string {
	return a.jsonPath
}

// OrderURL returns the Order URL for the ith Order the Account owns. An error
// is returned if the Account has no Orders or if the index is out of bounds.
func (a *Account) OrderURL(i int) (string, error) {
	if len(a.Orders) == 0 {
		return "", errors.New("Account has no orders")
	}
	if i < 0 || i >= len(a.Orders) {
		return "", fmt.Errorf("Order index must be 0 < x < %d", len(a.Orders))
	}
	return a.Orders[i], nil
}

// NewAccount creates an ACME account in-memory. *Important:* the
// created Account is *not* registered with the ACME server until
// it is explicitly "created" server-side using a Client instance's
// CreateAccount function.
//
// the emails argument is a slice of zero or more email addresses that should be
// used as the Account's Contact information.
//
// the privKey argument is a crypto.Signer to that should be used for
// the Account keypair. It will be used to create JWS for requests when the
// Account is a Client's ActiveAccount. If the privKey argument is nil a new
// randomly generated ECDSA private key will be used for the Account key.
func NewAccount(emails []string, privKey crypto.Signer) (*Account, error) {
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
		randKey, err := keys.NewSigner("ecdsa")
		if err != nil {
			return nil, err
		}
		privKey = randKey
	}

	return &Account{
		Contact: contacts,
		Signer:  privKey,
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
	account.jsonPath = path
	// write the serialized data to the provided filepath using a mode that only
	// allows access to the current user. This file contains a private key!
	return os.WriteFile(path, frozenBytes, 0600)
}

type rawAccount struct {
	ID         string
	Contact    []string
	Orders     []string
	KeyType    string
	PrivateKey []byte
}

func (a *Account) save() ([]byte, error) {
	keyBytes, keyType, err := keys.MarshalSigner(a.Signer)
	if err != nil {
		return nil, err
	}

	rawAcct := rawAccount{
		ID:         a.ID,
		Contact:    a.Contact,
		Orders:     a.Orders,
		KeyType:    keyType,
		PrivateKey: keyBytes,
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
	frozenBytes, err := os.ReadFile(path)
	if err != nil {
		return acct, err
	}

	err = acct.restore(frozenBytes)
	acct.jsonPath = path
	return acct, err
}

func (a *Account) restore(frozenAcct []byte) error {
	var rawAcct rawAccount

	if err := json.Unmarshal(frozenAcct, &rawAcct); err != nil {
		return err
	}

	privKey, err := keys.UnmarshalSigner(rawAcct.PrivateKey, rawAcct.KeyType)
	if err != nil {
		return err
	}

	a.ID = rawAcct.ID
	a.Contact = rawAcct.Contact
	a.Orders = rawAcct.Orders
	a.Signer = privKey
	return nil
}
