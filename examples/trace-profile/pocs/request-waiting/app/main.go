package main

import (
	"fmt"
	"log"
	"net/http"
	"syscall"
	"time"
)

const waitDuration = time.Second

func blockingSyscall() error {
	remaining := syscall.NsecToTimespec(waitDuration.Nanoseconds())
	for {
		var next syscall.Timespec
		err := syscall.Nanosleep(&remaining, &next)
		if err == nil {
			return nil
		}
		if err != syscall.EINTR {
			return err
		}
		remaining = next
	}
}

func runtimeWait() { time.Sleep(waitDuration) }

func main() {
	client := &http.Client{Timeout: 5 * time.Second}
	http.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ready") })
	http.HandleFunc("/syscall", func(w http.ResponseWriter, _ *http.Request) {
		if err := blockingSyscall(); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintln(w, "completed")
	})
	http.HandleFunc("/runtime", func(w http.ResponseWriter, _ *http.Request) {
		runtimeWait()
		fmt.Fprintln(w, "completed")
	})
	http.HandleFunc("/delay", func(w http.ResponseWriter, _ *http.Request) {
		runtimeWait()
		fmt.Fprintln(w, "completed")
	})
	http.HandleFunc("/downstream", func(w http.ResponseWriter, r *http.Request) {
		request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://127.0.0.1:8080/delay", nil)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		response, err := client.Do(request)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		response.Body.Close()
		fmt.Fprintln(w, "completed")
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
