package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
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

	fmt.Println("")
	fmt.Println("Step 1: Contract received by TOP")

	userToken := req.AccessToken
	if userToken == "" {
		userToken = req.Token
	}
	if userToken == "" {
		http.Error(w, "Missing access_token", http.StatusBadRequest)
		return
	}

	contractIDRaw, ok := req.Contract["contract_id"].(string)
	if !ok || contractIDRaw == "" {
		http.Error(w, "Missing contract_id", http.StatusBadRequest)
		return
	}

	fmt.Println("")
	fmt.Println("Step 2: contract_id extracted", contractIDRaw)

	fp := sha256.Sum256([]byte(userToken))
	tokenFingerprint := hex.EncodeToString(fp[:])
	if strings.EqualFold(os.Getenv("FORCE_TOKEN_MISMATCH"), "true") {
		tokenFingerprint = "deadbeef" + tokenFingerprint
	}

	backendBase := os.Getenv("BACKEND_URL")
	backendApiKey := os.Getenv("BACKEND_API_KEY")
	if backendBase == "" || backendApiKey == "" {
		http.Error(w, "TOP backend verification not configured", http.StatusInternalServerError)
		return
	}

	verifyURL := backendBase
	if verifyURL[len(verifyURL)-1] == '/' {
		verifyURL = verifyURL[:len(verifyURL)-1]
	}
	verifyURL = fmt.Sprintf("%s/p3dx/workloads/contracts/%s/token-verify", verifyURL, contractIDRaw)

	verifyBody, _ := json.Marshal(map[string]string{"token_fingerprint": tokenFingerprint})
	httpReq, err := http.NewRequest(http.MethodPost, verifyURL, bytes.NewReader(verifyBody))
	if err != nil {
		http.Error(w, "Token verification request build failed", http.StatusInternalServerError)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", backendApiKey)

	verifyHTTPResp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		http.Error(w, "Token verification failed", http.StatusBadGateway)
		return
	}
	defer verifyHTTPResp.Body.Close()

	bodyBytes, _ := io.ReadAll(verifyHTTPResp.Body)
	if verifyHTTPResp.StatusCode < 200 || verifyHTTPResp.StatusCode >= 300 {
		fmt.Println("backend token-verify non-2xx:", string(bodyBytes))
		http.Error(w, "Token verification rejected", http.StatusForbidden)
		return
	}

	var verifyResp struct {
		Status string `json:"status"`
		Match  bool   `json:"match"`
	}
	_ = json.Unmarshal(bodyBytes, &verifyResp)
	fmt.Println("")
	fmt.Println("Step 3: Backend token-verify response:", string(bodyBytes))
	if verifyResp.Status != "SUCCESS" || !verifyResp.Match {
		http.Error(w, "Token mismatch", http.StatusForbidden)
		return
	}

	fmt.Println("")
	fmt.Println("Step 4: User token fingerprint verified with backend")

	// --- DEVELOPMENT BYPASS START ---
	// To make this work locally without Keycloak, APD, and an Enclave running:

	// 1-3) Bypass token validation and consumer signature verification (development).
	// Keycloak-bound DPoP validation is not enabled in this POC path, so we skip strict claim checks.

	// 4) Marshal the contract bytes (used later for signing).
	contractBytes, err := json.Marshal(req.Contract)
	if err != nil {
		http.Error(w, "Invalid contract structure", http.StatusBadRequest)
		return
	}

	fmt.Println("")
	fmt.Println("Step 5: Contract marshaled (prepared for signing)")

	//
	// 5) Fetch policy from APD (mandatory).
	// The dataset id is read from contract.data_provider_terms.data_resource_id.
	datasetID := ""
	if dpt, ok := req.Contract["data_provider_terms"].(map[string]interface{}); ok {
		if raw, ok := dpt["data_resource_id"].(string); ok {
			datasetID = raw
		}
	}
	if datasetID == "" {
		http.Error(w, "Missing dataset id (data_provider_terms.data_resource_id)", http.StatusBadRequest)
		return
	}

	apdBase := strings.TrimSpace(os.Getenv("APD_BASE_URL"))
	if apdBase == "" {
		http.Error(w, "APD_BASE_URL not set", http.StatusInternalServerError)
		return
	}
	apdBase = strings.TrimSuffix(apdBase, "/")
	policyURL := fmt.Sprintf("%s/api/v1/policy/by-item/%s", apdBase, datasetID)
	policyResp, err := http.Get(policyURL)
	if err != nil {
		fmt.Println("APD policy fetch failed:", err)
		http.Error(w, "APD policy fetch failed", http.StatusBadGateway)
		return
	}
	defer policyResp.Body.Close()
	policyBody, _ := io.ReadAll(policyResp.Body)
	if policyResp.StatusCode >= 200 && policyResp.StatusCode < 300 {
		fmt.Println("")
		fmt.Println("Step 6: APD policy found for dataset", datasetID)
		fmt.Println("Policy fetched from APD for dataset", datasetID)
	} else if policyResp.StatusCode == http.StatusNotFound {
		fmt.Println("APD policy not found for dataset", datasetID)
		http.Error(w, "APD policy not found", http.StatusNotFound)
		return
	} else {
		fmt.Println("APD policy fetch non-2xx:", policyResp.StatusCode, string(policyBody))
		http.Error(w, "APD policy fetch failed", http.StatusBadGateway)
		return
	}

	//
	// 6) Store the unsigned contract artifact.
	// TOP stores a binary artifact and also writes a human-readable JSON for debugging.
	// Later, after embedding the orchestrator signature, the same files are overwritten.
	storeKey := []byte(os.Getenv("STORE_KEY"))
	if len(storeKey) != 32 {
		// fallback to a dummy 32-byte key if the env variable isn't set properly
		storeKey = []byte("12345678901234567890123456789012")
	}
	storePath := os.Getenv("STORE_PATH")
	if storePath == "" {
		storePath = "./" // Save to current directory instead of crashing
	}
	contractID := contractIDRaw
	_, err = services.SecureStoreWithID(req.Contract, storeKey, storePath, contractID)
	if err != nil {
		fmt.Println("Storage failed:", err)
		http.Error(w, "Storage failed", 500)
		return
	}

	fmt.Println("")
	fmt.Println("Step 7: Contract stored (initial artifact, before TOP signature)", contractID)

	// Save readable JSON contract for debugging (original)
	jsonPath := storePath + contractID + ".json"
	prettyContract, _ := json.MarshalIndent(req.Contract, "", "  ")
	if err := os.WriteFile(jsonPath, prettyContract, 0644); err != nil {
		fmt.Println("Failed to save readable JSON:", err)
	} else {
		fmt.Println("Readable contract saved to (initial):", jsonPath)
	}

	//
	// 7) Load the orchestrator private key and sign the contract bytes.
	// If the key is unavailable, TOP falls back to a mock signature.
	orchKeyPath := strings.TrimSpace(os.Getenv("ORCH_PRIVATE_KEY_PATH"))
	if orchKeyPath == "" {
		orchKeyPath = strings.TrimSpace(os.Getenv("ORCH_PRIVATE_KEY"))
	}
	priv, _ := services.LoadPrivateKey(orchKeyPath)
	var orchSig []byte
	if priv != nil {
		orchSig, _ = services.Sign(contractBytes, priv)
	} else {
		// Mock signature if key isn't loaded
		orchSig = []byte("mock-orchestrator-signature")
	}

	//
	// 8) Embed the orchestrator signature into contract.signatures.* (in-memory).
	sigs, ok := req.Contract["signatures"].(map[string]interface{})
	if !ok || sigs == nil {
		sigs = map[string]interface{}{}
		req.Contract["signatures"] = sigs
	}
	encodedOrchSig := base64.StdEncoding.EncodeToString(orchSig)
	sigs["orchestrator_signature"] = encodedOrchSig
	sigs["orchestrator_signature_algorithm"] = "RSA_PKCS1V15_SHA256"

	fmt.Println("")
	fmt.Println("Step 8: TOP signed & signature embedded into contract")

	signedAt, ok := sigs["signed_at"].(map[string]interface{})
	if !ok || signedAt == nil {
		signedAt = map[string]interface{}{}
		sigs["signed_at"] = signedAt
	}
	signedAt["orchestrator"] = time.Now().UTC().Format(time.RFC3339Nano)

	//
	// 9) Persist the signed contract artifact (overwrite the earlier unsigned files).
	_, err = services.SecureStoreWithID(req.Contract, storeKey, storePath, contractID)
	if err != nil {
		fmt.Println("Storage failed:", err)
		http.Error(w, "Storage failed", 500)
		return
	}

	fmt.Println("")
	fmt.Println("Step 9: Contract stored (overwritten with TOP signature)", contractID)

	// Overwrite readable JSON contract for debugging with signed version
	prettyContract, _ = json.MarshalIndent(req.Contract, "", "  ")
	if err := os.WriteFile(jsonPath, prettyContract, 0644); err != nil {
		fmt.Println("Failed to save readable JSON:", err)
	} else {
		fmt.Println("Readable contract saved to (overwritten, signed):", jsonPath)
	}

	//
	// 10) Resolve app_id -> compose_url from backend and trigger DeployEnclave.
	appID := ""
	if apt, ok := req.Contract["application_provider_terms"].(map[string]interface{}); ok {
		if raw, ok := apt["app_id"].(string); ok {
			appID = raw
		}
	}
	if appID == "" {
		http.Error(w, "Missing app_id (application_provider_terms.app_id)", http.StatusBadRequest)
		return
	}

	backendBase = strings.TrimSuffix(backendBase, "/")
	composeURL := fmt.Sprintf("%s/p3dx/apps/%s/compose-url", backendBase, appID)
	composeReq, err := http.NewRequest(http.MethodGet, composeURL, nil)
	if err != nil {
		http.Error(w, "Compose URL request build failed", http.StatusInternalServerError)
		return
	}
	composeReq.Header.Set("X-API-Key", backendApiKey)

	composeResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(composeReq)
	if err != nil {
		http.Error(w, "Compose URL fetch failed", http.StatusBadGateway)
		return
	}
	defer composeResp.Body.Close()
	composeBody, _ := io.ReadAll(composeResp.Body)
	if composeResp.StatusCode < 200 || composeResp.StatusCode >= 300 {
		fmt.Println("compose url fetch non-2xx:", composeResp.StatusCode, string(composeBody))
		http.Error(w, "Compose URL fetch failed", http.StatusBadGateway)
		return
	}

	var composePayload struct {
		Status     string `json:"status"`
		ComposeURL string `json:"compose_url"`
	}
	_ = json.Unmarshal(composeBody, &composePayload)
	if composePayload.Status != "SUCCESS" || composePayload.ComposeURL == "" {
		http.Error(w, "Compose URL missing", http.StatusBadGateway)
		return
	}

	fmt.Println("")
	fmt.Println("Step 10: compose-url fetched from backend for app_id", appID)

	consumerSig := req.Signature
	if consumerSig == "" {
		if sigs, ok := req.Contract["signatures"].(map[string]interface{}); ok {
			if raw, ok := sigs["consumer_signature"].(string); ok {
				consumerSig = raw
			}
		}
	}

	if err := services.DeployEnclave(services.DeployRequest{
		Contract:     req.Contract,
		Signature:    consumerSig,
		TopSignature: encodedOrchSig,
		ComposeURL:   composePayload.ComposeURL,
	}); err != nil {
		fmt.Println("TEE deploy failed:", err)
		http.Error(w, "TEE deploy failed", http.StatusBadGateway)
		return
	}

	fmt.Println("")
	fmt.Println("Step 11: DeployEnclave called")
	fmt.Println("")
	fmt.Println("Step 12: TEE started")
	fmt.Println("--------------------------------------------------------------------------------")

	// --- DEVELOPMENT BYPASS END ---

	resp := map[string]string{
		"status":         "success",
		"orch_signature": hex.EncodeToString(orchSig),
		"contract_id":    contractID,
	}

	json.NewEncoder(w).Encode(resp)
}
