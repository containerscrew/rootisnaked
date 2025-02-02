package main

import (
	"sync"

	devstdout "github.com/containerscrew/devstdout/pkg"
	commitcreds "github.com/containerscrew/rootisnaked/program/commit_creds"
	filepermissions "github.com/containerscrew/rootisnaked/program/file_perm"
)

func main() {
	log := devstdout.NewLogger(
		devstdout.OptionsLogger{Level: "info", AddSource: false, LoggerType: "pretty"},
	)

	log.Success("Starting rootisnaked...")

	var wg sync.WaitGroup

	// Start commitcreds program
	wg.Add(1)
	go func() {
		defer wg.Done()
		commitcreds.GetCommitCreds(log)
	}()

	// Start filepermissions program
	wg.Add(1)
	go func() {
		defer wg.Done()
		filepermissions.FilePermissions(log)
	}()

	// Wait for all goroutines to finish
	wg.Wait()
}

// func main() {
// 	log := devstdout.NewLogger(
// 		devstdout.OptionsLogger{Level: "info", AddSource: false, LoggerType: "pretty"},
// 	)

// 	log.Success("Starting rootisnaked...")

// 	// Running multiple programs probabnly will need to implement a way to run them in a go routine
// 	commitcreds.GetCommitCreds(log)

// 	// filepermissions.FilePermissions(log)
// }
