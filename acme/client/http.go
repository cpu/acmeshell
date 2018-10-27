package client

import (
	"net/http"

	"github.com/cpu/acmeshell/net"
)

func (c *Client) handleRequest(req *http.Request) (*net.NetResponse, error) {
	resp, err := c.net.Do(req)
	if err != nil {
		return nil, err
	}
	/*
		if opts.PrintRequest {
			log.Printf("Request:\n%s\n", resp.ReqDump)
		}
		if opts.PrintResponse {
			log.Printf("Response:\n%s\n", resp.RespDump)
		}
	*/
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
