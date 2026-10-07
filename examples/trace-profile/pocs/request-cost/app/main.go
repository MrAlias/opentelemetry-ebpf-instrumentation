package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
	"time"
)

var requests atomic.Uint64

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", func(w http.ResponseWriter, _ *http.Request) {
		var value uint64
		if requests.Add(1)%4 == 0 {
			value = rebuildEntry(800 * time.Millisecond)
		} else {
			value = readEntry(150 * time.Millisecond)
		}
		fmt.Fprintf(w, "%016x\n", value)
	})
	mux.HandleFunc("GET /report", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%016x\n", exportReport(2*time.Second))
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second}
	log.Fatal(server.ListenAndServe())
}

//go:noinline
func readEntry(duration time.Duration) uint64 {
	end, value := time.Now().Add(duration), uint64(1)
	for time.Now().Before(end) {
		for i := 0; i < 100_000; i++ {
			value ^= value << 13
			value ^= value >> 7
			value ^= value << 17
		}
	}
	return value
}

//go:noinline
func rebuildEntry(duration time.Duration) uint64 {
	end, value := time.Now().Add(duration), uint64(1)
	for time.Now().Before(end) {
		for i := 0; i < 100_000; i++ {
			value = (value ^ (value >> 11)) * 0x9e3779b185ebca87
		}
	}
	return value
}

//go:noinline
func exportReport(duration time.Duration) uint64 {
	end, value := time.Now().Add(duration), uint64(1)
	for time.Now().Before(end) {
		for i := 0; i < 100_000; i++ {
			value = (value << 5) ^ (value >> 2) ^ uint64(i)
		}
	}
	return value
}
