package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const workDuration = 5 * time.Second

func main() {
	scenario := os.Getenv("DEMO_SCENARIO")
	if scenario != "" && scenario != "cpu" && scenario != "waiting" {
		log.Fatal("DEMO_SCENARIO must be cpu or waiting")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", workload(scenario != "waiting"))
	mux.HandleFunc("GET /report", workload(scenario == "waiting"))
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}

func workload(cpu bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cpu {
			checksum := burnCPU(r.Context(), workDuration)
			fmt.Fprintf(w, "checksum=%016x\n", checksum)
			return
		}

		timer := time.NewTimer(workDuration)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			fmt.Fprintln(w, "ok")
		}
	}
}

func burnCPU(ctx context.Context, duration time.Duration) uint64 {
	deadline := time.Now().Add(duration)
	checksum := uint64(1)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			break
		}
		for i := 0; i < 100_000; i++ {
			checksum ^= checksum << 13
			checksum ^= checksum >> 7
			checksum ^= checksum << 17
		}
	}
	return checksum
}
