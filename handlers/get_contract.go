package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func HandleGetContract(w http.ResponseWriter, r *http.Request) {
	// Expected paths:
	// - /contracts/{contractId}
	prefix := "/contracts/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	contractID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, prefix))
	if contractID == "" {
		http.Error(w, "Missing contract_id", http.StatusBadRequest)
		return
	}

	storePath := os.Getenv("STORE_PATH")
	if storePath == "" {
		storePath = "./"
	}

	jsonPath := filepath.Join(storePath, contractID+".json")
	b, err := os.ReadFile(jsonPath)
	if err != nil {
		http.Error(w, "Contract not found", http.StatusNotFound)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(b, &payload); err != nil {
		http.Error(w, "Invalid stored contract", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "SUCCESS",
		"contract": payload,
	})
}
