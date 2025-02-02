package main

import (
	devstdout "github.com/containerscrew/devstdout/pkg"
	commitcreds "github.com/containerscrew/rootisnaked/program/commit_creds"
)

func main() {
	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: "info", AddSource: false, LoggerType: "pretty"},
	)

	log.Success("Starting rootisnaked...")

	// Running multiple programs probabnly will need to implement a way to run them in a go routine
	commitcreds.GetCommitCreds(log)

	// filepermissions.FilePermissions(log)
}
