package client

import (
	"log"
	"net/http"

	"github.com/cpu/acmeshell/net"
)

func (c *Client) handleRequest(req *http.Request) (*net.NetResponse, error) {
	resp, err := c.net.Do(req)
	if err != nil {
		return nil, err
	}
	if c.Output.PrintRequests {
		log.Printf("Request:\n%s\n", resp.ReqDump)
	}
	if c.Output.PrintResponses {
		log.Printf("Response:\n%s\n", resp.RespDump)
	}
	return resp, nil
}

func (c *Client) GetURL(url string) (*net.NetResponse, error) {
	req, err := c.net.GetRequest(url)
	if err != nil {
		return nil, err
	}
	return c.handleRequest(req)
}

func (c *Client) PostURL(url string, body []byte) (*net.NetResponse, error) {
	req, err := c.net.PostRequest(url, body)
	if err != nil {
		return nil, err
	}
	return c.handleRequest(req)
}

func (c *Client) PostAsGetURL(url string) (*net.NetResponse, error) {
	// Sign the POST-as-GET body
	signResult, err := c.Sign(url, []byte(""), nil)
	if err != nil {
		return nil, err
	}

	return c.PostURL(url, signResult.SerializedJWS)
}
