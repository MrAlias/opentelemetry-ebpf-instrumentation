package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

type checkoutRequest struct {
	CartID string `json:"cart_id"`
	Coupon string `json:"coupon"`
	SKU    string `json:"sku"`
}

type checkoutResponse struct {
	CartID        string `json:"cart_id"`
	Coupon        string `json:"coupon,omitempty"`
	SubtotalCents int64  `json:"subtotal_cents"`
	TotalCents    int64  `json:"total_cents"`
	DurationMS    int64  `json:"duration_ms"`
}

type inventoryProduct struct {
	SKU        string `json:"sku"`
	Available  int    `json:"available"`
	PriceCents int64  `json:"price_cents"`
}

var inventoryClient = &http.Client{Timeout: 2 * time.Second}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "18080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /checkout", checkout)

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	log.Printf("checkout listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func checkout(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	var request checkoutRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if err := validateCart(request.CartID); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.SKU == "" {
		request.SKU = "frog-plush"
	}
	product, err := fetchInventory(r.Context(), request.SKU)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	subtotal := calculateSubtotal(request.CartID, product.PriceCents)
	total := applyCoupon(request.Coupon, subtotal)
	if err := chargePayment(request.CartID, total); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(checkoutResponse{
		CartID: request.CartID, Coupon: request.Coupon,
		SubtotalCents: subtotal, TotalCents: total,
		DurationMS: time.Since(started).Milliseconds(),
	})
}

//go:noinline
func fetchInventory(ctx context.Context, sku string) (inventoryProduct, error) {
	endpoint := os.Getenv("JAVA_INVENTORY_URL")
	if endpoint == "" {
		endpoint = "http://inventory-java:18082/availability"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?sku="+url.QueryEscape(sku), nil)
	if err != nil {
		return inventoryProduct{}, err
	}
	response, err := inventoryClient.Do(request)
	if err != nil {
		return inventoryProduct{}, fmt.Errorf("inventory lookup failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return inventoryProduct{}, fmt.Errorf("inventory lookup returned %s", response.Status)
	}
	var product inventoryProduct
	if err := json.NewDecoder(response.Body).Decode(&product); err != nil {
		return inventoryProduct{}, fmt.Errorf("decode inventory response: %w", err)
	}
	return product, nil
}

//go:noinline
func validateCart(cartID string) error {
	time.Sleep(8 * time.Millisecond)
	if cartID == "" {
		return errors.New("cart_id is required")
	}
	return nil
}

//go:noinline
func calculateSubtotal(cartID string, unitPriceCents int64) int64 {
	time.Sleep(12 * time.Millisecond)
	return unitPriceCents*5 + int64(len(cartID))
}

//go:noinline
func applyCoupon(code string, subtotal int64) int64 {
	if code == "" {
		return subtotal
	}

	// Deliberate demo fault: a synchronous remote coupon lookup on every request.
	time.Sleep(900 * time.Millisecond)
	if code == "FROG20" {
		return subtotal * 80 / 100
	}
	return subtotal
}

//go:noinline
func chargePayment(cartID string, total int64) error {
	time.Sleep(18 * time.Millisecond)
	if total <= 0 {
		return fmt.Errorf("invalid total for cart %s", cartID)
	}
	return nil
}
