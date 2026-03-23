package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// Contract is the payload sent to the enclave deploy API.
type Contract map[string]interface{}

type DeployRequest struct {
	Contract     Contract `json:"contract"`
	Signature    string   `json:"signature"`
	TopSignature string   `json:"topSignature"`
	ComposeURL   string   `json:"compose_url"`
}

// DeployEnclave POSTs the contract and signatures to the enclave service.
func DeployEnclave(req DeployRequest) error {
	dryRunRaw := strings.TrimSpace(os.Getenv("TEE_DEPLOY_DRY_RUN"))
	dryRun := dryRunRaw == "" || strings.EqualFold(dryRunRaw, "true") || dryRunRaw == "1" || strings.EqualFold(dryRunRaw, "yes")
	if dryRun {
		fmt.Println("TEE deploy dry-run: skipping HTTP call")
		return nil
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		return err
	}

	deployURL := strings.TrimSpace(os.Getenv("TEE_DEPLOY_URL"))
	if deployURL == "" {
		deployURL = strings.TrimSpace(os.Getenv("ENCLAVE_DEPLOY_URL"))
	}
	if deployURL == "" {
		deployURL = "http://localhost:8080/deployEnclave"
	}

	client := &http.Client{}

	request, err := http.NewRequest(
		"POST",
		deployURL,
		bytes.NewBuffer(jsonData),
	)
	if err != nil {
		return err
	}

	request.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("deployment failed with status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	return nil
}
