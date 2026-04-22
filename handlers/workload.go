package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"top/contract"
)

// WorkloadRequest is the payload sent by p3dx-aaa to POST /workload.
type WorkloadRequest struct {
	AccessToken   string `json:"access_token"`
	DatasetID     string `json:"dataset_id"`
	ApplicationID string `json:"application_id"`
}

// HandleWorkload is the new ConMan-merged endpoint.
// It accepts a raw workload request, creates the contract internally,
// consumer-signs it, then runs the full orchestrator pipeline.
//
// POST /workload
//
//	{ "access_token": "...", "dataset_id": "...", "application_id": "..." }
func HandleWorkload(w http.ResponseWriter, r *http.Request) {
	var req WorkloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.AccessToken) == "" {
		http.Error(w, "Missing access_token", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DatasetID) == "" {
		http.Error(w, "Missing dataset_id", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.ApplicationID) == "" {
		http.Error(w, "Missing application_id", http.StatusBadRequest)
		return
	}

	fmt.Println("")
	fmt.Println("Step 1: Workload request received")
	fmt.Printf("        dataset_id=%s  application_id=%s\n", req.DatasetID, req.ApplicationID)

	// ---- Step 2: Extract JWT claims -----------------------------------------
	claims, err := contract.ExtractClaims(req.AccessToken)
	if err != nil {
		fmt.Println("JWT claim extraction failed:", err)
		http.Error(w, "Invalid access_token: "+err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Println("")
	fmt.Println("Step 2: JWT claims extracted (user:", claims.UserID+")")

	// ---- Step 3: Create contract struct -------------------------------------
	c, err := contract.CreateContract(req.AccessToken, req.DatasetID, req.ApplicationID)
	if err != nil {
		fmt.Println("Contract creation failed:", err)
		http.Error(w, "Contract creation failed", http.StatusInternalServerError)
		return
	}
	fmt.Println("")
	fmt.Println("Step 3: Contract created  id:", c.ContractID)

	// ---- Step 4: Consumer signature (HMAC-SHA256) ---------------------------
	secretRaw := strings.TrimSpace(os.Getenv("CONTRACT_SERVER_SECRET"))
	if secretRaw == "" {
		http.Error(w, "CONTRACT_SERVER_SECRET not set", http.StatusInternalServerError)
		return
	}
	if err := contract.SignWithKeycloakSession(c, claims, []byte(secretRaw)); err != nil {
		fmt.Println("Consumer signing failed:", err)
		http.Error(w, "Consumer signing failed", http.StatusInternalServerError)
		return
	}
	fmt.Println("")
	fmt.Println("Step 4: Consumer signature computed")

	// ---- Convert typed struct → map[string]interface{} for pipeline ---------
	// Marshal then unmarshal so the pipeline operates on the same generic map
	// representation used by the existing contract.go handler.
	contractBytes, err := json.Marshal(c)
	if err != nil {
		http.Error(w, "Contract serialisation failed", http.StatusInternalServerError)
		return
	}
	var contractMap map[string]interface{}
	if err := json.Unmarshal(contractBytes, &contractMap); err != nil {
		http.Error(w, "Contract deserialisation failed", http.StatusInternalServerError)
		return
	}

	// ---- Steps 5–10: APD fetch, store, sign, store, compose-url, deploy -----
	// stepOffset=4 so pipeline prints Step 5, 6, 7, 8, 9, 10, 11
	result, ok := RunContractPipeline(w, contractMap, c.ContractID, 4)
	if !ok {
		return // error already written to w
	}

	// ---- Return signed contract to caller -----------------------------------
	resp := map[string]interface{}{
		"status":      "success",
		"contract_id": c.ContractID,
		"contract":    result.ContractMap,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
