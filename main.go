package main

import (
	"log"

	"github.com/containerscrew/rootisnaked/program"
)

func main() {
	log.Print("Starting rootisnaked")

	program.GetCommitCreds()
}
