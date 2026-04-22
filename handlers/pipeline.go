package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"top/services"
)

// PipelineResult holds the output of a successful RunContractPipeline call.
type PipelineResult struct {
	ContractMap      map[string]interface{} // signed contract (with orchestrator signature embedded)
	OrchSigEncoded   string                 // base64-encoded orchestrator signature
	OrchSigHex       string                 // hex-encoded orchestrator signature (for response field)
}

// RunContractPipeline runs the shared contract processing steps:
//
//	APD policy fetch → store unsigned → orchestrator sign → store signed → compose-url fetch → DeployEnclave
//
// On any error it writes the appropriate HTTP error to w and returns ok=false.
// The caller must not write to w after a false return.
func RunContractPipeline(
	w http.ResponseWriter,
	contractMap map[string]interface{},
	contractID string,
	stepOffset int, // added to step numbers in log output so each handler can keep its own numbering
) (*PipelineResult, bool) {

	step := func(n int, msg string, args ...interface{}) {
		fmt.Printf("\nStep %d: %s\n", n+stepOffset, fmt.Sprintf(msg, args...))
	}

	// ---- APD policy fetch ---------------------------------------------------
	datasetID := ""
	if dpt, ok := contractMap["data_provider_terms"].(map[string]interface{}); ok {
		if raw, ok := dpt["data_resource_id"].(string); ok {
			datasetID = raw
		}
	}
	if datasetID == "" {
		http.Error(w, "Missing dataset id (data_provider_terms.data_resource_id)", http.StatusBadRequest)
		return nil, false
	}

	apdBase := strings.TrimSuffix(strings.TrimSpace(os.Getenv("APD_BASE_URL")), "/")
	if apdBase == "" {
		http.Error(w, "APD_BASE_URL not set", http.StatusInternalServerError)
		return nil, false
	}
	policyURL := fmt.Sprintf("%s/api/v1/policy/by-item/%s", apdBase, datasetID)
	policyResp, err := http.Get(policyURL)
	if err != nil {
		fmt.Println("APD policy fetch failed:", err)
		http.Error(w, "APD policy fetch failed", http.StatusBadGateway)
		return nil, false
	}
	defer policyResp.Body.Close()
	policyBody, _ := io.ReadAll(policyResp.Body)
	if policyResp.StatusCode == http.StatusNotFound {
		fmt.Println("APD policy not found for dataset", datasetID)
		http.Error(w, "APD policy not found", http.StatusNotFound)
		return nil, false
	} else if policyResp.StatusCode < 200 || policyResp.StatusCode >= 300 {
		fmt.Println("APD policy fetch non-2xx:", policyResp.StatusCode, string(policyBody))
		http.Error(w, "APD policy fetch failed", http.StatusBadGateway)
		return nil, false
	}
	step(1, "APD policy found for dataset %s", datasetID)

	// ---- Storage setup ------------------------------------------------------
	storeKey := []byte(os.Getenv("STORE_KEY"))
	if len(storeKey) != 32 {
		storeKey = []byte("12345678901234567890123456789012")
	}
	storePath := os.Getenv("STORE_PATH")
	if storePath == "" {
		storePath = "./"
	}

	// ---- Marshal contract bytes (for signing) --------------------------------
	contractBytes, err := json.Marshal(contractMap)
	if err != nil {
		http.Error(w, "Invalid contract structure", http.StatusBadRequest)
		return nil, false
	}

	// ---- Store unsigned contract --------------------------------------------
	if _, err = services.SecureStoreWithID(contractMap, storeKey, storePath, contractID); err != nil {
		fmt.Println("Storage failed:", err)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return nil, false
	}
	jsonPath := storePath + contractID + ".json"
	prettyContract, _ := json.MarshalIndent(contractMap, "", "  ")
	_ = os.WriteFile(jsonPath, prettyContract, 0644)
	step(2, "Contract stored (unsigned) %s", contractID)

	// ---- Orchestrator signing -----------------------------------------------
	orchKeyPath := strings.TrimSpace(os.Getenv("ORCH_PRIVATE_KEY_PATH"))
	if orchKeyPath == "" {
		orchKeyPath = strings.TrimSpace(os.Getenv("ORCH_PRIVATE_KEY"))
	}
	priv, _ := services.LoadPrivateKey(orchKeyPath)
	var orchSig []byte
	if priv != nil {
		orchSig, _ = services.Sign(contractBytes, priv)
	} else {
		orchSig = []byte("mock-orchestrator-signature")
	}

	sigs, ok := contractMap["signatures"].(map[string]interface{})
	if !ok || sigs == nil {
		sigs = map[string]interface{}{}
		contractMap["signatures"] = sigs
	}
	encodedOrchSig := base64.StdEncoding.EncodeToString(orchSig)
	sigs["orchestrator_signature"] = encodedOrchSig
	sigs["orchestrator_signature_algorithm"] = "RSA_PKCS1V15_SHA256"

	signedAt, ok := sigs["signed_at"].(map[string]interface{})
	if !ok || signedAt == nil {
		signedAt = map[string]interface{}{}
		sigs["signed_at"] = signedAt
	}
	signedAt["orchestrator"] = time.Now().UTC().Format(time.RFC3339Nano)
	step(3, "Orchestrator signature embedded")

	// ---- Store signed contract (overwrite) ----------------------------------
	if _, err = services.SecureStoreWithID(contractMap, storeKey, storePath, contractID); err != nil {
		fmt.Println("Storage failed:", err)
		http.Error(w, "Storage failed", http.StatusInternalServerError)
		return nil, false
	}
	prettyContract, _ = json.MarshalIndent(contractMap, "", "  ")
	_ = os.WriteFile(jsonPath, prettyContract, 0644)
	step(4, "Contract stored (signed) %s", contractID)

	// ---- Compose-URL fetch --------------------------------------------------
	appID := ""
	if apt, ok := contractMap["application_provider_terms"].(map[string]interface{}); ok {
		if raw, ok := apt["app_id"].(string); ok {
			appID = raw
		}
	}
	if appID == "" {
		http.Error(w, "Missing app_id (application_provider_terms.app_id)", http.StatusBadRequest)
		return nil, false
	}

	backendBase := strings.TrimSuffix(os.Getenv("BACKEND_URL"), "/")
	backendApiKey := os.Getenv("BACKEND_API_KEY")
	if backendBase == "" || backendApiKey == "" {
		http.Error(w, "BACKEND_URL or BACKEND_API_KEY not configured", http.StatusInternalServerError)
		return nil, false
	}

	composeReq, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/p3dx/apps/%s/compose-url", backendBase, appID), nil)
	if err != nil {
		http.Error(w, "Compose URL request build failed", http.StatusInternalServerError)
		return nil, false
	}
	composeReq.Header.Set("X-API-Key", backendApiKey)

	composeResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(composeReq)
	if err != nil {
		http.Error(w, "Compose URL fetch failed", http.StatusBadGateway)
		return nil, false
	}
	defer composeResp.Body.Close()
	composeBody, _ := io.ReadAll(composeResp.Body)
	if composeResp.StatusCode < 200 || composeResp.StatusCode >= 300 {
		fmt.Println("compose url fetch non-2xx:", composeResp.StatusCode, string(composeBody))
		http.Error(w, "Compose URL fetch failed", http.StatusBadGateway)
		return nil, false
	}

	var composePayload struct {
		Status     string `json:"status"`
		ComposeURL string `json:"compose_url"`
	}
	_ = json.Unmarshal(composeBody, &composePayload)
	if composePayload.Status != "SUCCESS" || composePayload.ComposeURL == "" {
		http.Error(w, "Compose URL missing", http.StatusBadGateway)
		return nil, false
	}
	step(5, "Compose URL fetched for app_id %s", appID)

	// ---- DeployEnclave ------------------------------------------------------
	consumerSig := ""
	if sigs != nil {
		if raw, ok := sigs["consumer_signature"].(string); ok {
			consumerSig = raw
		}
	}

	if err := services.DeployEnclave(services.DeployRequest{
		Contract:     contractMap,
		Signature:    consumerSig,
		TopSignature: encodedOrchSig,
		ComposeURL:   composePayload.ComposeURL,
	}); err != nil {
		fmt.Println("TEE deploy failed:", err)
		http.Error(w, "TEE deploy failed", http.StatusBadGateway)
		return nil, false
	}

	step(6, "DeployEnclave called")
	step(7, "TEE started")
	fmt.Println("--------------------------------------------------------------------------------")

	return &PipelineResult{
		ContractMap:    contractMap,
		OrchSigEncoded: encodedOrchSig,
		OrchSigHex:     fmt.Sprintf("%x", orchSig),
	}, true
}
