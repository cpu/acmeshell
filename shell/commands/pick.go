package commands

import (
	"errors"
	"fmt"
	"sort"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
)

func PickOrderURL(c *ishell.Context) (string, error) {
	client := GetClient(c)
	if len(client.ActiveAccount.Orders) == 0 {
		return "", fmt.Errorf("active account has no orders")
	}

	orderList := make([]string, len(client.ActiveAccount.Orders))
	for i, orderURL := range client.ActiveAccount.Orders {
		line := fmt.Sprintf("%3d) %s", i, orderURL)
		orderList[i] = line
	}

	choice := c.MultiChoice(orderList, "Select an order")
	return client.ActiveAccount.Orders[choice], nil
}

func PickOrder(c *ishell.Context) (*resources.Order, error) {
	client := GetClient(c)

	orderURL, err := PickOrderURL(c)
	if err != nil {
		return nil, err
	}
	order := &resources.Order{
		ID: orderURL,
	}
	err = client.UpdateOrder(order)
	if err != nil {
		return nil, err
	}
	return order, nil
}

func PickAuthzURL(c *ishell.Context, order *resources.Order) (string, error) {
	if len(order.Authorizations) == 0 {
		return "", errors.New("order has no authorizations")
	}

	choice := c.MultiChoice(order.Authorizations, "Choose an authorization")
	return order.Authorizations[choice], nil
}

func PickAuthz(c *ishell.Context, order *resources.Order) (*resources.Authorization, error) {
	client := GetClient(c)

	identifiersToAuthz := make(map[string]*resources.Authorization)
	for _, authzURL := range order.Authorizations {
		authz := &resources.Authorization{
			ID: authzURL,
		}
		err := client.UpdateAuthz(authz)
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

func PickChall(c *ishell.Context, authz *resources.Authorization) (*resources.Challenge, error) {
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
