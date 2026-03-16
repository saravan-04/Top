package handlers

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"top/services"

)

type Request struct {
	// Token can be sent either as `access_token` (matching Keycloak token response)
	AccessToken string                 `json:"access_token"`
	Token       string                 `json:"token"`
	Contract    map[string]interface{} `json:"contract"`
	Signature   string                 `json:"signature"` // hex-encoded user signature of the contract
}

func HandleContract(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// --- DEVELOPMENT BYPASS START ---
	// To make this work locally without Keycloak, APD, and an Enclave running:
	
	// 1-3. Bypass Token Validation and Signature check
	// Because Keycloak needs to return a valid DPoP token and a bound JWK, which we don't have.
	// We'll skip validating claims altogether.

	// 2. Marshal contract bytes to store later
	contractBytes, err := json.Marshal(req.Contract)
	if err != nil {
		http.Error(w, "Invalid contract structure", http.StatusBadRequest)
		return
	}

	// 4. Bypass APD check (assumes it always passes for now)
	fmt.Println("Bypassed APD authorization for local testing.")

	// 5. Load orchestrator private key (or bypass if empty)
	priv, _ := services.LoadPrivateKey(os.Getenv("ORCH_PRIVATE_KEY"))
	var orchSig []byte
	if priv != nil {
		orchSig, _ = services.Sign(contractBytes, priv)
	} else {
		// Mock signature if key isn't loaded
		orchSig = []byte("mock-orchestrator-signature")
	}

	// 6. Secure store (Saving the encrypted contract to a file)
	storeKey := []byte(os.Getenv("STORE_KEY"))
	if len(storeKey) != 32 {
		// fallback to a dummy 32-byte key if the env variable isn't set properly
		storeKey = []byte("12345678901234567890123456789012") 
	}
	storePath := os.Getenv("STORE_PATH")
	if storePath == "" {
		storePath = "./" // Save to current directory instead of crashing
	}

	contractID, err := services.SecureStore(req.Contract, storeKey, storePath)
	if err != nil {
		fmt.Println("Storage failed:", err)
		http.Error(w, "Storage failed", 500)
		return
	}

	// NEW: Save readable JSON contract for debugging
	jsonPath := storePath + contractID + ".json"
	prettyContract, _ := json.MarshalIndent(req.Contract, "", "  ")
	if err := os.WriteFile(jsonPath, prettyContract, 0644); err != nil {
		fmt.Println("Failed to save readable JSON:", err)
	} else {
		fmt.Println("Readable contract saved to:", jsonPath)
	}

	// 8. Bypass Deploy to enclave (TEE) Network Call
	fmt.Println("Bypassed Enclave Deployment for local testing.")
	
	// --- DEVELOPMENT BYPASS END ---

	resp := map[string]string{
		"status":         "success",
		"orch_signature": hex.EncodeToString(orchSig),
		"contract_id":    contractID,
	}

	json.NewEncoder(w).Encode(resp)
}
