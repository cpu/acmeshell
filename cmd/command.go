package cmd

import (
	"log"
)

func FailOnError(err error, msg string) {
	// If there wasn't an error, return
	if err == nil {
		return
	}

	// Otherwise, print the error and fail
	log.Fatalf("[!] %s - %s", msg, err)
}
