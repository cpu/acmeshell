package client

import (
	"encoding/json"
	"log"
)

func (c *Client) getDirectory() (map[string]any, error) {
	url := c.DirectoryURL.String()

	resp, err := c.net.GetURL(url)
	if err != nil {
		return nil, err
	}

	var directory map[string]any
	err = json.Unmarshal(resp.RespBody, &directory)
	if err != nil {
		return nil, err
	}

	return directory, nil
}

// Directory fetches the ACME Directory resource from the ACME server and
// returns it deserialized as a map.
//
// See https://tools.ietf.org/html/rfc8555#section-7.1.1
func (c *Client) Directory() (map[string]any, error) {
	if c.directory == nil {
		if err := c.UpdateDirectory(); err != nil {
			return nil, err
		}
	}

	return c.directory, nil
}

// UpdateDirectory updates the Client's cached directory used when referencing
// the endpoints for updating nonces, creating accounts, and creating orders.
//
// TODO(@cpu): I don't think it makes sense for both Directory and
// UpdateDirectory to be exported/defined on the client.
func (c *Client) UpdateDirectory() error {
	newDir, err := c.getDirectory()
	if err != nil {
		return err
	}

	c.directory = newDir
	log.Printf("Updated directory")
	return nil
}

// GetEndpintURL gets a URL for a specific ACME endpoint URL by first fetching
// the ACME server's directory and then checking that directory resource for the
// a key with the given name. If the key is found its value is returned along
// with a true bool. If the key is not found an empty string is returned with
// a false bool.
func (c *Client) GetEndpointURL(name string) (string, bool) {
	dir, err := c.Directory()
	if err != nil {
		return "", false
	}
	rawURL, ok := dir[name]
	if !ok {
		return "", false
	}
	switch v := rawURL.(type) {
	case string:
		if v == "" {
			return "", false
		}
		return v, true
	}
	return "", false
}
