//go:build debug

package main

import (
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
)

const pprofPort = 6060

func init() {
	go func() {
		addr := fmt.Sprintf(":%d", pprofPort)
		fmt.Printf("[debug] pprof server listening on %s\n", addr)
		if err := http.ListenAndServe(addr, nil); err != nil { //nolint:gosec
			log.Printf("[debug] pprof server error: %v\n", err)
		}
	}()
}
