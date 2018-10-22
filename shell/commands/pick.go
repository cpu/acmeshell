package commands

import (
	"fmt"
	"sort"

	"github.com/abiosoft/ishell"
	"github.com/cpu/acmeshell/acme/resources"
)

func PickOrder(c *ishell.Context) (*resources.Order, error) {
	client := GetClient(c)
	if len(client.ActiveAccount.Orders) == 0 {
		return nil, fmt.Errorf("active account has no orders")
	}

	orderList := make([]string, len(client.ActiveAccount.Orders))
	for i, order := range client.ActiveAccount.Orders {
		line := fmt.Sprintf("%3d)", i)
		line += fmt.Sprintf("\t%#q", order)

		// TODO(@cpu): Restore identifiers
		/*
			var domains []string
			for _, d := range order.Identifiers {
				domains = append(domains, d.Value)
			}
			line += fmt.Sprintf("\t%s", strings.Join(domains, ","))
		*/
		orderList[i] = line
	}

	choice := c.MultiChoice(orderList, "Select an order")
	orderURL := client.ActiveAccount.Orders[choice]
	var order = &resources.Order{
		ID: orderURL,
	}
	err := client.UpdateOrder(order, nil)
	if err != nil {
		return nil, err
	}
	return order, nil
}

func PickAuthz(c *ishell.Context, order *resources.Order) (*resources.Authorization, error) {
	client := GetClient(c)

	identifiersToAuthz := make(map[string]*resources.Authorization)
	for _, authzURL := range order.Authorizations {
		authz := &resources.Authorization{
			ID: authzURL,
		}
		err := client.UpdateAuthz(authz, nil)
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
