package client

import (
	"log"
	"net/http"

	"github.com/cpu/acmeshell/net"
)

type HTTPOptions struct {
	PrintResponse bool
	PrintRequest  bool
}

// TODO(@cpu): update this
type HTTPPostOptions struct {
	HTTPOptions
	PrintJWS       bool
	PrintJWSObject bool
	PrintJSON      bool
}

var (
	defaultHTTPOptions = &HTTPOptions{
		PrintRequest:  false,
		PrintResponse: false,
	}
	defaultHTTPPostOptions = &HTTPPostOptions{
		HTTPOptions:    *defaultHTTPOptions,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	}
)

func (c *Client) handleRequest(req *http.Request, opts *HTTPOptions) (*net.NetResponse, error) {
	if opts == nil {
		opts = defaultHTTPOptions
	}
	resp, err := c.net.Do(req)
	if err != nil {
		return nil, err
	}
	if opts.PrintRequest {
		log.Printf("Request:\n%s\n", resp.ReqDump)
	}
	if opts.PrintResponse {
		log.Printf("Response:\n%s\n", resp.RespDump)
	}
	return resp, nil
}

func (c *Client) GetURL(url string, opts *HTTPOptions) (*net.NetResponse, error) {
	// TODO(@cpu): Just use net.GetURL
	req, err := c.net.GetRequest(url)
	if err != nil {
		return nil, err
	}
	return c.handleRequest(req, opts)
}

func (c *Client) PostURL(url string, body []byte, opts *HTTPOptions) (*net.NetResponse, error) {
	// TODO(@cpu): Just use net.PostURL
	req, err := c.net.PostRequest(url, body)
	if err != nil {
		return nil, err
	}
	return c.handleRequest(req, opts)
}
