package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Payment struct {
	ID        string    `json:"id"`
	Amount    float64   `json:"amount"`
	Currency  string    `json:"currency"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	mu       sync.Mutex
	payments = map[string]Payment{}
)

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "pay_" + hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func createPayment(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Amount   float64 `json:"amount"`
		Currency string  `json:"currency"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil || in.Amount <= 0 || in.Currency == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid amount or currency"})
		return
	}
	p := Payment{ID: newID(), Amount: in.Amount, Currency: in.Currency, Status: "created", CreatedAt: time.Now().UTC()}
	mu.Lock()
	payments[p.ID] = p
	mu.Unlock()
	writeJSON(w, http.StatusCreated, p)
}

func getPayment(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	p, ok := payments[r.PathValue("id")]
	mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("POST /payments", createPayment)
	mux.HandleFunc("GET /payments/{id}", getPayment)

	addr := ":" + getenv("PORT", "8080")
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("novapay-api listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
