//go:build e2e
// +build e2e

// Copyright (c) 2020 Red Hat, Inc.
// Copyright Contributors to the Open Cluster Management project

package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"
	"testing"
)

// TestRunMain wraps the main() function in order to build a test binary and collection coverage for
// E2E/Integration tests. Controller CLI flags are also passed in here.
func TestRunMain(t *testing.T) {
	os.Args = append(os.Args, "--leader-elect=false")

	// the pprof server will run here
	go func() {
		log.Error(http.ListenAndServe("localhost:6060", nil), "Problem serving localhost:6060")
	}()

	main()
}
