---
title: "ACME Shell"
type: "homepage"
date: 2018-10-20T16:07:32-04:00
---

ACME Shell is a low level shell based ACME client tailored for ACME
client/server developers. It supports both interactive and non-interactive
usage.

## Quickstart

1. [Set up Go](https://golang.org/doc/install) and your `$GOPATH`
2. `go get -u github.com/letsencrypt/pebble/...`
3. `go get -u github.com/cpu/acmeshell/...`
4. `PEBBLE_WFE_NONCEREJECT=0 pebble -dnsserver 127.0.0.1:5252 &`
5. `acmeshell -pebble`

This will start a Pebble ACME server and an ACME shell instance ready to use it.
An ACME account will automatically be created with the server when you start
`acmeshell`.

## Warning

ACME Shell is **not finished**. The code is yucky and your experience using it
might be too!

ACME Shell is targetted at **developers** - not server administrators. Do not use
ACME Shell to issue/renew your production certificates. Do not write automation
around ACME Shell to manage real certificates and keypairs. Instead, use 
a [real](https://github.com/certbot/certbot/) [acme](https://github.com/xenolf/lego) [client](https://github.com/Neilpang/acme.sh) (or use [a fully fledged library](https://pypi.org/project/acme/)).

## Features

* Built-in challenge server for returning HTTP-01 and TLS-ALPN-01 challenge
  responses.
* Built-in mock DNS server for DNS-01 challenges and directing
  HTTP-01/TLS-ALPN-01 requests to the built-in challenge server.
* Convenient interactive shell supporting autocompletion of commands and menu
  selection of ACME objects.
* Powerful templating support for convenient manual construction of
  authenticated protocol messages.
* Create, save/load and switch between many ACME accounts.
* Non-interactive usage suitable for scripts and automated tests.
