package client

import (
	"encoding/json"
	"net/http"
)

type HTTPOptions struct {
	PrintHeaders  bool
	PrintStatus   bool
	PrintResponse bool
}

type HTTPPostOptions struct {
	HTTPOptions
	PrintJWS       bool
	PrintJWSObject bool
	PrintJSON      bool
}

type ResponseCtx struct {
	Body []byte
	Resp *http.Response
	Err  error
}

var (
	defaultHTTPOptions = &HTTPOptions{
		PrintHeaders:  false,
		PrintStatus:   false,
		PrintResponse: false,
	}
	defaultHTTPPostOptions = &HTTPPostOptions{
		HTTPOptions:    *defaultHTTPOptions,
		PrintJWS:       false,
		PrintJWSObject: false,
		PrintJSON:      false,
	}
)

func (c *Client) GetURL(url string, opts *HTTPOptions) ResponseCtx {
	respBody, resp, err := c.net.GetURL(url)
	return c.handleResponse(ResponseCtx{respBody, resp, err}, opts)
}

func (c *Client) PostURL(url string, body []byte, opts *HTTPOptions) ResponseCtx {
	respBody, resp, err := c.net.PostURL(url, body)
	return c.handleResponse(ResponseCtx{respBody, resp, err}, opts)
}

func (c *Client) handleResponse(respCtx ResponseCtx, opts *HTTPOptions) ResponseCtx {
	c.printHTTPResponse(respCtx, opts)
	return respCtx
}

func (c *Client) printHTTPResponse(respCtx ResponseCtx, opts *HTTPOptions) {
	if opts == nil {
		opts = defaultHTTPOptions
	}
	if opts.PrintStatus {
		if respCtx.Resp != nil {
			c.Printf("Response Status: %s\n", respCtx.Resp.Status)
		} else {
			c.Printf("Response was nil\n")
		}
	}
	if opts.PrintHeaders {
		headerBytes, _ := json.MarshalIndent(&respCtx.Resp.Header, "", "  ")
		c.Printf("Response Headers: \n%s\n", string(headerBytes))
	}
	if opts.PrintResponse {
		c.Printf("Response body:\n%s\n", string(respCtx.Body))
	}
}
