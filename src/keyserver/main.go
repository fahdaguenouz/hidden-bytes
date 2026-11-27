// Key server for Hidden-Bytes C2 key management.
// Stores AES-256 keys at encryption time and serves them to runners at execution time.
//
// Usage:
//
//	keyserver --addr 0.0.0.0:8080
//	keyserver --addr 0.0.0.0:8080 --burn   (delete key after first fetch)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
)

type keyEntry struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}

type storeKeyRequest struct {
	Key   string `json:"key"`
	Nonce string `json:"nonce"`
}

type storeKeyResponse struct {
	KeyID string `json:"key_id"`
}

var (
	keys   = make(map[string]keyEntry)
	mu     sync.RWMutex
	burn   bool
)

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func handleStore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req storeKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Key == "" || req.Nonce == "" {
		http.Error(w, "key and nonce required", http.StatusBadRequest)
		return
	}

	id := generateID()

	mu.Lock()
	keys[id] = keyEntry{Key: req.Key, Nonce: req.Nonce}
	mu.Unlock()

	fmt.Fprintf(os.Stderr, "[KEY-STORE] Stored key_id=%s\n", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(storeKeyResponse{KeyID: id})
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "missing key id", http.StatusBadRequest)
		return
	}

	if burn {
		mu.Lock()
		entry, ok := keys[id]
		if ok {
			delete(keys, id)
			fmt.Fprintf(os.Stderr, "[KEY-FETCH] Served and burned key_id=%s\n", id)
		}
		mu.Unlock()
		if !ok {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(entry)
		return
	}

	mu.RLock()
	entry, ok := keys[id]
	mu.RUnlock()

	if !ok {
		http.Error(w, "key not found", http.StatusNotFound)
		return
	}

	fmt.Fprintf(os.Stderr, "[KEY-FETCH] Served key_id=%s\n", id)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entry)
}

func handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}

	mu.RLock()
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"count": len(ids),
		"keys":  ids,
	})
}

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "listen address")
	flag.BoolVar(&burn, "burn", false, "delete key after first fetch (burn-after-reading)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /keys", handleStore)
	mux.HandleFunc("GET /keys/{id}", handleFetch)
	mux.HandleFunc("GET /keys", handleList)

	fmt.Fprintf(os.Stderr, "[KEYSERVER] Listening on %s", *addr)
	if burn {
		fmt.Fprint(os.Stderr, " (burn-after-reading enabled)")
	}
	fmt.Fprintln(os.Stderr)

	if err := http.ListenAndServe(*addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		os.Exit(1)
	}
}
