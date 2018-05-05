package net

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"runtime"
	"strings"
)

const (
	version       = "0.0.1"
	userAgentBase = "cpu.acmeshell"
	locale        = "en-us"
)

type Config struct {
	CABundlePath string
}

func (c *Config) normalize() error {
	// Strip spaces from both config fields
	c.CABundlePath = strings.TrimSpace(c.CABundlePath)

	if c.CABundlePath == "" {
		return fmt.Errorf("CABundlePath must not be empty")
	}

	// It's good!
	return nil
}

type ACMENet struct {
	httpClient *http.Client
}

func New(conf Config) (*ACMENet, error) {
	if err := conf.normalize(); err != nil {
		return nil, err
	}

	pemBundle, err := ioutil.ReadFile(conf.CABundlePath)
	if err != nil {
		return nil, err
	}

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(pemBundle)

	return &ACMENet{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs: caBundle,
				},
			},
		},
	}, nil
}

func (c *ACMENet) httpRequest(req *http.Request) ([]byte, *http.Response, error) {
	ua := fmt.Sprintf("%s %s (%s; %s)",
		userAgentBase, version, runtime.GOOS, runtime.GOARCH)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept-Language", locale)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	return respBody, resp, nil
}

func (c *ACMENet) HeadURL(url string) (*http.Response, error) {
	log.Printf("Sending HEAD request to URL %q\n", url)
	return c.httpClient.Head(url)
}

func (c *ACMENet) PostURL(url string, body []byte) ([]byte, *http.Response, error) {
	log.Printf("Sending POST request to URL %q\n", url)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/jose+json")
	return c.httpRequest(req)
}

func (c *ACMENet) GetURL(url string) ([]byte, *http.Response, error) {
	log.Printf("Sending GET request to URL %q\n", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	return c.httpRequest(req)
}
