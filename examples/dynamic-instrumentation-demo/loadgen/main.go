package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	target := envOr("CHECKOUT_URL", "http://checkout:18080/checkout")
	interval, err := time.ParseDuration(envOr("REQUEST_INTERVAL", "250ms"))
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for sequence := 1; ; sequence++ {
		coupon := ""
		if sequence%4 == 0 {
			coupon = "FROG20"
		}
		body := fmt.Sprintf(`{"cart_id":"cart-%06d","coupon":"%s","sku":"frog-plush"}`, sequence, coupon)
		request, err := http.NewRequest(http.MethodPost, target, bytes.NewBufferString(body))
		if err == nil {
			request.Header.Set("Content-Type", "application/json")
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_, _ = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			} else {
				log.Printf("checkout request failed: %v", requestErr)
			}
		}
		time.Sleep(interval)
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
