package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestApplyCoupon(t *testing.T) {
	t.Parallel()

	if got := applyCoupon("FROG20", 10000); got != 8000 {
		t.Fatalf("applyCoupon(FROG20) = %d, want 8000", got)
	}
	if got := applyCoupon("", 10000); got != 10000 {
		t.Fatalf("applyCoupon(empty) = %d, want 10000", got)
	}
}

func TestFetchInventory(t *testing.T) {
	originalClient := inventoryClient
	t.Cleanup(func() { inventoryClient = originalClient })
	inventoryClient = &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if got := request.URL.Query().Get("sku"); got != "frog plush" {
			t.Fatalf("sku = %q, want frog plush", got)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(strings.NewReader(`{"sku":"frog plush","available":7,"price_cents":2050}`)),
		}, nil
	})}
	t.Setenv("JAVA_INVENTORY_URL", "http://inventory.test/availability")

	product, err := fetchInventory(t.Context(), "frog plush")
	if err != nil {
		t.Fatal(err)
	}
	if product.Available != 7 || product.PriceCents != 2050 {
		t.Fatalf("product = %+v", product)
	}
}
