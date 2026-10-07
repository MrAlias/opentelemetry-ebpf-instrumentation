package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const reportDuration = 2 * time.Second
const controlWait = 1900 * time.Millisecond
const completionDuration = 100 * time.Millisecond

type application struct {
	shared   bool
	resource sync.Mutex
	result   atomic.Uint64
	requests atomic.Uint64
}

func groundTruth(event, path string, request uint64, resource *sync.Mutex) {
	row := map[string]any{"time": time.Now().UTC().Format(time.RFC3339Nano), "event": event, "path": path, "request": request}
	if resource != nil {
		row["resource"] = fmt.Sprintf("%p", resource)
	}
	data, _ := json.Marshal(row)
	fmt.Fprintln(os.Stderr, string(data))
}

//go:noinline
func prepareReport(duration time.Duration) uint64 {
	deadline := time.Now().Add(duration)
	value := uint64(1)
	for time.Now().Before(deadline) {
		for range 100000 {
			value = value*6364136223846793005 + 1442695040888963407
		}
	}
	return value
}

//go:noinline
func finishWork(duration time.Duration) uint64 {
	deadline := time.Now().Add(duration)
	value := uint64(7)
	for time.Now().Before(deadline) {
		for range 100000 {
			value = value*2862933555777941757 + 3037000493
		}
	}
	return value
}

func (a *application) report(w http.ResponseWriter, _ *http.Request) {
	id := a.requests.Add(1)
	a.resource.Lock()
	groundTruth("acquired", "/report", id, &a.resource)
	a.result.Store(prepareReport(reportDuration))
	groundTruth("releasing", "/report", id, &a.resource)
	a.resource.Unlock()
	fmt.Fprintln(w, "report complete")
}

func (a *application) work(w http.ResponseWriter, _ *http.Request) {
	id := a.requests.Add(1)
	if a.shared {
		groundTruth("waiting", "/work", id, &a.resource)
		a.resource.Lock()
		groundTruth("acquired", "/work", id, &a.resource)
		a.resource.Unlock()
	} else {
		groundTruth("waiting", "/work", id, nil)
		time.Sleep(controlWait)
		groundTruth("resumed", "/work", id, nil)
	}
	a.result.Store(finishWork(completionDuration))
	fmt.Fprintln(w, "work complete")
}

func main() {
	scenario := os.Getenv("SCENARIO")
	if scenario != "shared-lock" && scenario != "control" {
		log.Fatal("SCENARIO must be shared-lock or control")
	}
	runtime.GOMAXPROCS(2)
	app := &application{shared: scenario == "shared-lock"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /work", app.work)
	mux.HandleFunc("GET /report", app.report)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ready") })
	server := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(server.ListenAndServe())
}
