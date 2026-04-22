package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Request is the payload for the legacy POST /contract endpoint.
// p3dx-aaa sends a pre-built contract here in the old flow.
// New callers should use POST /workload instead.
type Request struct {
	// Token can be sent either as `access_token` (matching Keycloak token response)
	AccessToken string                 `json:"access_token"`
	Token       string                 `json:"token"`
	Contract    map[string]interface{} `json:"contract"`
	Signature   string                 `json:"signature"` // hex-encoded user signature of the contract
}

// HandleContract is the legacy endpoint that accepts a pre-built, consumer-signed
// contract from p3dx-aaa and runs the orchestrator pipeline (policy check → sign → deploy).
//
// POST /contract
//
//	{ "access_token": "...", "contract": { ... }, "signature": "..." }
//
// Token fingerprint verification (old Steps 3–4) has been removed — TOP now owns
// contract creation via POST /workload, making the anti-substitution callback redundant.
func HandleContract(w http.ResponseWriter, r *http.Request) {
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	fmt.Println("")
	fmt.Println("Step 1: Contract received by TOP (legacy /contract endpoint)")

	userToken := req.AccessToken
	if userToken == "" {
		userToken = req.Token
	}
	if userToken == "" {
		http.Error(w, "Missing access_token", http.StatusBadRequest)
		return
	}

	contractID, ok := req.Contract["contract_id"].(string)
	if !ok || contractID == "" {
		http.Error(w, "Missing contract_id", http.StatusBadRequest)
		return
	}

	fmt.Println("")
	fmt.Println("Step 2: contract_id extracted:", contractID)

	// Steps 3–4 (token fingerprint verification callback to p3dx-aaa) have been
	// removed. Contract creation now happens inside TOP (POST /workload), so TOP
	// has the original token from the start and the anti-substitution check is
	// no longer needed here.

	// Steps 3–9 (APD fetch, store, sign, store, compose-url, deploy) via shared pipeline.
	// stepOffset=2 so pipeline prints Step 3, 4, 5, 6, 7, 8, 9
	result, ok2 := RunContractPipeline(w, req.Contract, contractID, 2)
	if !ok2 {
		return // error already written to w
	}

	resp := map[string]string{
		"status":         "success",
		"orch_signature": result.OrchSigHex,
		"contract_id":    contractID,
	}
	json.NewEncoder(w).Encode(resp)
}
