# p3dx-top — Trusted Orchestrator Protocol

TOP is the contract creation, validation, and TEE provisioning component of the P3DX platform, written in Go.

When a user runs a workload, the p3dx-aaa backend forwards the raw workload parameters to TOP. TOP owns the full contract lifecycle: it creates the contract from scratch, computes the consumer HMAC signature, fetches the dataset policy from APD, signs the contract with the orchestrator key, stores the signed artifact to disk, and triggers TEE deployment. The fully signed contract is returned to p3dx-aaa in a single response.

---

## What this repo does

- Receives raw workload parameters (`access_token`, `dataset_id`, `application_id`) from p3dx-aaa
- Extracts JWT claims from the access token to identify the consumer
- Creates the full contract struct (UUID, 90-day lifecycle, parties, dataset/app terms)
- Computes the consumer HMAC-SHA256 signature using `CONTRACT_SERVER_SECRET`
- Fetches the dataset access policy from APD — rejects the contract if no policy exists
- Stores the unsigned contract to disk (AES-256-GCM encrypted `.bin` + plain `.json`)
- Signs the contract with the orchestrator RSA private key and embeds the signature
- Overwrites the stored contract with the signed version
- Resolves the application's docker-compose URL from the backend and triggers TEE deployment
- Returns the fully signed contract to p3dx-aaa in a single response
- Exposes a read endpoint so p3dx-aaa can retrieve the stored signed contract for the UI

A legacy `POST /contract` endpoint is also kept for backward compatibility. It accepts a pre-built contract from the caller and runs the same orchestrator-signing pipeline (steps 5–11 only — contract creation and consumer signing happen on the caller's side).

---

## Repository Structure

```
Top/
├── main.go              # Entry point — registers routes and starts HTTP server
├── handlers/
│   ├── workload.go      # POST /workload — primary endpoint; owns full contract lifecycle
│   ├── contract.go      # POST /contract — legacy; accepts a pre-built contract
│   ├── pipeline.go      # Shared pipeline: APD fetch → store → sign → deploy
│   └── get_contract.go  # GET /contracts/:contractId — retrieve stored signed contract
├── contract/
│   ├── contract.go      # Contract struct + CreateContract() + ExtractClaims()
│   └── sign.go          # Consumer HMAC-SHA256 signing (SignWithKeycloakSession)
├── services/
│   ├── store.go         # AES-256-GCM encrypted binary artifact storage
│   ├── crypto.go        # RSA key loading + signing (PKCS1v15 SHA-256)
│   ├── tee.go           # DeployEnclave — dry-run or real HTTP call
│   ├── apd.go           # APD policy fetch
│   └── keycloak.go      # JWT/token utilities
├── config/
│   └── config.go        # Env var helpers
├── keys/                # Orchestrator key material
└── go.mod
```

---

## Getting Started

### Prerequisites

- Go 1.22+
- p3dx-aaa backend running and reachable
- APD running and reachable
- (Optional) RSA private key for orchestrator signing — mock signature used if absent

### Configure

Create a `.env` file in the repo root (loaded automatically via `godotenv`):

```env
PORT=8085

# Backend (p3dx-aaa) — used for compose URL resolution
BACKEND_URL=http://localhost:3001
BACKEND_API_KEY=<shared secret — must match TOP_BACKEND_API_KEY in p3dx-aaa .env>

# APD — used to fetch dataset policy before accepting a workload
APD_BASE_URL=http://localhost:8082

# Consumer signing — HMAC-SHA256 secret used in POST /workload
CONTRACT_SERVER_SECRET=<same value as CONTRACT_SERVER_SECRET used previously>

# Contract storage
STORE_PATH=./              # Directory where {contractId}.bin and {contractId}.json are written
STORE_KEY=<32-byte string> # Encryption key for binary artifact storage

# Orchestrator signing key (RSA private key, PEM format)
# If not set, TOP falls back to a mock signature
ORCH_PRIVATE_KEY_PATH=./keys/orchestrator_private_key.pem

# TEE deployment
# true (default): skip real HTTP call, log "TEE started" and proceed
# false: make real HTTP call to TEE_DEPLOY_URL
TEE_DEPLOY_DRY_RUN=true
TEE_DEPLOY_URL=http://localhost:9999/deployEnclave
```

### Run

```bash
go run .
```

Expected output:
```
TOP running on port 8085
```

---

## API Endpoints

| Method | Path | Caller | Description |
|---|---|---|---|
| `POST` | `/workload` | p3dx-aaa | **Primary.** Accept raw workload params, create + sign contract, deploy TEE |
| `POST` | `/contract` | legacy callers | Accept a pre-built contract, run orchestrator signing + deploy pipeline |
| `GET` | `/contracts/:contractId` | p3dx-aaa | Return the stored signed contract JSON |

All endpoints are unauthenticated at the HTTP level — they are intended to be reachable only on the internal/trusted network.

---

## POST /workload — Full Pipeline

Accepts `{ access_token, dataset_id, application_id }` from p3dx-aaa and runs all 11 steps:

```
Step 1   Workload request received
Step 2   JWT claims extracted from access_token (sub, sid, iat, exp)
Step 3   Contract struct created (UUID contract_id, 90-day lifecycle, parties, terms)
Step 4   Consumer HMAC-SHA256 signature computed (CONTRACT_SERVER_SECRET)
           → embedded in contract.signatures.consumer_signature
Step 5   Dataset policy fetched from APD
           GET {APD_BASE_URL}/api/v1/policy/by-item/{datasetId}
           → 404  →  reject (404)
           → non-2xx  →  reject (502)
Step 6   Unsigned contract stored to disk ({contractId}.bin + {contractId}.json)
Step 7   Orchestrator RSA signature computed (PKCS1v15-SHA256)
           → embedded in contract.signatures.orchestrator_signature
Step 8   Signed contract stored to disk (overwrites step 6 files)
Step 9   Docker Compose URL fetched from backend
           GET {BACKEND_URL}/p3dx/apps/{appId}/compose-url
           Header: X-API-Key
Step 10  DeployEnclave called with signed contract + compose URL
Step 11  TEE started

Response: { "status": "success", "contract_id": "...", "contract": { ... } }
```

---

## POST /contract — Legacy Pipeline (Steps 5–11 only)

Accepts a pre-built contract from the caller. The caller is responsible for contract creation and consumer signing. TOP then runs steps 5–11 of the pipeline: APD policy fetch, unsigned storage, orchestrator signing, signed storage, compose-URL resolution, and TEE deployment.

This endpoint is kept for backward compatibility and is no longer called by p3dx-aaa in the standard workload flow.

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `8085` | HTTP listen port |
| `BACKEND_URL` | Yes | — | p3dx-aaa base URL (for compose-url callback) |
| `BACKEND_API_KEY` | Yes | — | Shared key for `X-API-Key` callbacks to p3dx-aaa |
| `APD_BASE_URL` | Yes | — | APD base URL (for policy fetch) |
| `CONTRACT_SERVER_SECRET` | Yes (for `/workload`) | — | HMAC-SHA256 secret for consumer signing |
| `STORE_PATH` | No | `./` | Directory for contract artifact files |
| `STORE_KEY` | No | dummy 32-byte key | AES-256-GCM encryption key for binary storage |
| `ORCH_PRIVATE_KEY_PATH` | No | — | RSA private key for orchestrator signing; mock signature used if absent |
| `TEE_DEPLOY_DRY_RUN` | No | `true` | Skip real TEE deploy HTTP call |
| `TEE_DEPLOY_URL` | No | `http://localhost:8080/deployEnclave` | TEE deploy endpoint (used when `TEE_DEPLOY_DRY_RUN=false`) |

---

## Contract Structure

The signed contract JSON written to disk and returned in the response:

```json
{
  "contract_id": "<uuid>",
  "version": 1,
  "description": "workload dataset=<id> application=<id>",
  "lifecycle": { "created_at", "valid_from", "valid_until" },
  "execution_type": "TRAINING",
  "execution_platform": "AZURE_AMD_SEV",
  "parties": {
    "data_provider":        { "id", "name", "organization_id", "public_key" },
    "application_provider": { "id", "name", "organization_id", "public_key" },
    "consumer":             { "id" (= Keycloak sub), "name", "public_key" }
  },
  "data_provider_terms":        { "data_resource_id", "dataset_name", ... },
  "application_provider_terms": { "app_id", "app_name", ... },
  "consumer_terms":             { "selected_app_id", "datablob_url", ... },
  "signatures": {
    "contract_hash": "...",
    "consumer_signature": "<base64 HMAC-SHA256>",
    "orchestrator_signature": "<base64 RSA-PKCS1v15-SHA256>",
    "orchestrator_signature_algorithm": "RSA_PKCS1V15_SHA256",
    "signed_at": { "consumer": "<RFC3339>", "orchestrator": "<RFC3339>" }
  }
}
```

---

## More Information

See the p3dx-aaa `Setup.md` for the full end-to-end workload flow and how TOP fits into the P3DX platform.
