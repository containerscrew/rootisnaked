package main

import (
	devstdout "github.com/containerscrew/devstdout/pkg"
	"github.com/containerscrew/rootisnaked/program"
)

func main() {
	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: "info", AddSource: false, LoggerType: "console"},
	)

	log.Success("Starting rootisnaked...")

	program.GetCommitCreds(log)
}
