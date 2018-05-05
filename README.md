# ACME Shell

Low level shell based [ACME](https://tools.ietf.org/html/draft-ietf-acme-acme-14) client tailored for ACME client/server developers. Supports both interactive and non-interactive usage.

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

ACMEShell is targetted at **developers** - not server administrators. Do not use
ACMEShell to issue/renew your production certificates. Do not write automation
around ACMEShell to manage real certificates and keypairs. Get
a [real](https://github.com/certbot/certbot/) [acme](https://github.com/xenolf/lego) [client](https://github.com/Neilpang/acme.sh) instead (or use [a library](https://pypi.org/project/acme/)).

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

## Usage Guide

### Account Management

#### Auto-register

#### Save account

#### Load accounts

#### List accounts

#### Switch account

### Key Management

#### Create keys

#### Save keys

#### Load keys

#### Create a CSR

### Basic workflow

#### Manually constructing messages

##### Templating

#### Higher level commands

#### End-to-end certificate issuance

### Non-interactive Usage

### Misc Features

#### Signing messages

#### CSR manipulation

#### Challenge server

#### Base64URL encode/decode
