package contract

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---- Structs ----------------------------------------------------------------

type Lifecycle struct {
	CreatedAt  time.Time `json:"created_at"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until"`
}

type Party struct {
	ID             string `json:"id,omitempty"`
	Name           string `json:"name"`
	OrganizationID string `json:"organization_id,omitempty"`
	PublicKey      string `json:"public_key"`
}

type Parties struct {
	DataProvider        Party `json:"data_provider"`
	ApplicationProvider Party `json:"application_provider"`
	Consumer            Party `json:"consumer"`
}

type Constraints struct {
	AccessibilityLevel string `json:"accessibility_level,omitempty"`
	Restricted         string `json:"restricted,omitempty"`
}

type UsageConstraints struct {
	MaxRequests  int    `json:"max_requests,omitempty"`
	MaxBatchSize int    `json:"max_batch_size,omitempty"`
	ResultFormat string `json:"result_format,omitempty"`
}

type DataProviderTerms struct {
	DataResourceID string      `json:"data_resource_id"`
	DatasetName    string      `json:"dataset_name"`
	DatasetVersion string      `json:"dataset_version"`
	DataURL        string      `json:"data_url"`
	DataHash       string      `json:"data_hash"`
	Format         string      `json:"format"`
	DataSizeBytes  int64       `json:"data_size_bytes"`
	LicenseType    string      `json:"license_type"`
	Constraints    Constraints `json:"constraints,omitempty"`
}

type ApplicationProviderTerms struct {
	AppID           string           `json:"app_id"`
	AppName         string           `json:"app_name"`
	AppVersion      string           `json:"app_version"`
	AppHash         string           `json:"app_hash"`
	ContainerImage  string           `json:"container_image"`
	ContainerDigest string           `json:"container_digest"`
	Constraints     Constraints      `json:"constraints,omitempty"`
	Usage           UsageConstraints `json:"usage_constraints,omitempty"`
}

type ConsumerTerms struct {
	SelectedAppID      string           `json:"selected_app_id"`
	SelectedAppVersion string           `json:"selected_app_version"`
	DataBlobURL        string           `json:"datablob_url"`
	UsageConstraints   UsageConstraints `json:"usage_constraints,omitempty"`
	DataRetention      string           `json:"consumer_data_retention_policy,omitempty"`
}

type SignatureTimes struct {
	DataProvider        *time.Time `json:"data_provider,omitempty"`
	ApplicationProvider *time.Time `json:"application_provider,omitempty"`
	Consumer            *time.Time `json:"consumer,omitempty"`
	APD                 *time.Time `json:"apd,omitempty"`
}

type Signatures struct {
	ContractHash                 string         `json:"contract_hash"`
	SignatureAlgorithm           string         `json:"signature_algorithm"`
	DataProviderSignature        string         `json:"data_provider_signature,omitempty"`
	ApplicationProviderSignature string         `json:"application_provider_signature,omitempty"`
	ConsumerSignature            string         `json:"consumer_signature,omitempty"`
	APDSignature                 string         `json:"apd_signature,omitempty"`
	SignedAt                     SignatureTimes `json:"signed_at"`
}

type Contract struct {
	ContractID               string                   `json:"contract_id"`
	Version                  int                      `json:"version"`
	Description              string                   `json:"description"`
	Lifecycle                Lifecycle                `json:"lifecycle"`
	ExecutionType            string                   `json:"execution_type"`
	ExecutionPlatform        string                   `json:"execution_platform"`
	Parties                  Parties                  `json:"parties"`
	DataProviderTerms        DataProviderTerms        `json:"data_provider_terms"`
	ApplicationProviderTerms ApplicationProviderTerms `json:"application_provider_terms"`
	ConsumerTerms            ConsumerTerms            `json:"consumer_terms"`
	Signatures               Signatures               `json:"signatures"`
}

// ---- JWT claim extraction ---------------------------------------------------

type KCClaims struct {
	UserID    string
	SessionID string
	Expiry    int64
	IssuedAt  int64
}

type jwtPayload struct {
	Sub string `json:"sub"`
	Sid string `json:"sid"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// ExtractClaims base64-decodes the JWT payload segment and parses the claims
// needed for contract creation and consumer signing.
func ExtractClaims(token string) (KCClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return KCClaims{}, fmt.Errorf("invalid JWT: expected at least 2 parts, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return KCClaims{}, fmt.Errorf("JWT payload decode failed: %w", err)
	}

	var p jwtPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return KCClaims{}, fmt.Errorf("JWT payload unmarshal failed: %w", err)
	}

	if p.Sub == "" {
		return KCClaims{}, fmt.Errorf("JWT missing sub claim")
	}

	// sid is not always present in all Keycloak configs; allow empty.
	return KCClaims{
		UserID:    p.Sub,
		SessionID: p.Sid,
		IssuedAt:  p.Iat,
		Expiry:    p.Exp,
	}, nil
}

// ---- Contract creation ------------------------------------------------------

// CreateContract builds a new Contract from the raw workload parameters.
// It extracts user identity from the JWT and populates all required fields.
// The returned contract has no signatures yet — call SignWithKeycloakSession next.
func CreateContract(token, datasetID, applicationID string) (*Contract, error) {
	claims, err := ExtractClaims(token)
	if err != nil {
		return nil, fmt.Errorf("claim extraction failed: %w", err)
	}

	created := time.Now().UTC()
	expires := created.Add(90 * 24 * time.Hour)

	c := &Contract{
		ContractID:  uuid.NewString(),
		Version:     1,
		Description: fmt.Sprintf("workload dataset=%s application=%s", datasetID, applicationID),

		Lifecycle: Lifecycle{
			CreatedAt:  created,
			ValidFrom:  created,
			ValidUntil: expires,
		},

		ExecutionType:     "TRAINING",
		ExecutionPlatform: "AZURE_AMD_SEV",

		Parties: Parties{
			DataProvider: Party{
				ID:             "dp-uuid-placeholder",
				Name:           "Data Provider",
				OrganizationID: "dp-org-placeholder",
				PublicKey:      "ed25519:DP_PUBLIC_KEY_BASE64",
			},
			ApplicationProvider: Party{
				ID:             "ap-uuid-placeholder",
				Name:           "Application Provider",
				OrganizationID: "ap-org-placeholder",
				PublicKey:      "ed25519:AP_PUBLIC_KEY_BASE64",
			},
			Consumer: Party{
				ID:        claims.UserID,
				Name:      "Keycloak User",
				PublicKey: "ed25519:USER_PUBLIC_KEY_BASE64",
			},
		},

		DataProviderTerms: DataProviderTerms{
			DataResourceID: datasetID,
			DatasetName:    datasetID,
			DatasetVersion: "v1",
			DataURL:        "https://example.invalid/data",
			DataHash:       "sha256:placeholder",
			Format:         "UNKNOWN",
			DataSizeBytes:  0,
			LicenseType:    "UNKNOWN",
			Constraints: Constraints{
				AccessibilityLevel: "PUBLIC",
			},
		},

		ApplicationProviderTerms: ApplicationProviderTerms{
			AppID:           applicationID,
			AppName:         applicationID,
			AppVersion:      "v1",
			AppHash:         "sha256:placeholder",
			ContainerImage:  "registry.example.com/app:latest",
			ContainerDigest: "sha256:placeholder",
			Constraints: Constraints{
				AccessibilityLevel: "PUBLIC",
			},
			Usage: UsageConstraints{
				MaxRequests:  10000,
				MaxBatchSize: 256,
			},
		},

		ConsumerTerms: ConsumerTerms{
			SelectedAppID:      applicationID,
			SelectedAppVersion: "v1",
			DataBlobURL:        "https://example.invalid/blob",
			UsageConstraints: UsageConstraints{
				MaxRequests:  10000,
				MaxBatchSize: 256,
				ResultFormat: "JSON",
			},
			DataRetention: "DELETE_AFTER_EXECUTION",
		},
	}

	return c, nil
}
