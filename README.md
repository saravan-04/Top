# p3dx-top — Trusted Orchestrator Protocol

TOP is the contract ingestion and TEE provisioning component of the P3DX platform, written in Go.

When a user runs a workload, the p3dx-aaa backend generates a signed contract and submits it to TOP. TOP validates the contract, fetches the dataset policy from APD, signs the contract on the orchestrator side, and triggers TEE deployment.

---

## What this repo does

- Receives workload contracts from the p3dx-aaa backend
- Verifies that the user token TOP received matches the token used to create the contract (anti-substitution fingerprint check via backend callback)
- Fetches the dataset access policy from APD — rejects the contract if no policy exists
- Signs the contract with the orchestrator private key and embeds the signature
- Stores the fully signed contract to disk
- Resolves the application's docker-compose URL from the backend and triggers TEE deployment
- Exposes a read endpoint so the backend can retrieve the final signed contract for the UI

---

## Repository Structure

```
Top/
├── main.go              # Entry point — registers routes and starts HTTP server
├── handlers/
│   ├── contract.go      # POST /contract — full ingestion pipeline
│   └── get_contract.go  # GET /contracts/:contractId — read stored contract
├── services/
│   ├── store.go         # Encrypted binary artifact storage
│   ├── crypto.go        # RSA signing (PKCS1v15 SHA-256)
│   ├── tee.go           # DeployEnclave — dry-run or real HTTP call
│   ├── apd.go           # APD policy fetch
│   └── keycloak.go      # Token utilities
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
- (Optional) RSA private key for orchestrator signing

### Configure

Create a `.env` file in the repo root (loaded automatically via `godotenv`):

```env
PORT=8085

# Backend (p3dx-aaa) — used for token fingerprint verification and compose URL resolution
BACKEND_URL=http://localhost:3001
BACKEND_API_KEY=<shared secret — must match TOP_BACKEND_API_KEY in p3dx-aaa .env>

# APD — used to fetch dataset policy before accepting a contract
APD_BASE_URL=http://localhost:8082

# Contract storage
STORE_PATH=./           # Directory where {contractId}.bin and {contractId}.json are written
STORE_KEY=<32-byte string>  # Encryption key for binary artifact storage

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
| `POST` | `/contract` | p3dx-aaa backend | Ingest a workload contract — runs full validation and signing pipeline |
| `GET` | `/contracts/:contractId` | p3dx-aaa backend | Return the stored signed contract JSON |

Both endpoints are unauthenticated at the HTTP level — they are intended to be reachable only on the internal network. The `/contract` endpoint does its own token fingerprint verification by calling back to the p3dx-aaa backend with `X-API-Key`.

---

## Contract Ingestion Pipeline (POST /contract)

```
Step 1   Contract received from backend
Step 2   contract_id extracted
Step 3   SHA-256 fingerprint computed from user token
Step 4   Fingerprint verified with backend
           POST {BACKEND_URL}/p3dx/workloads/contracts/{contractId}/token-verify
           Header: X-API-Key
           → match: false  →  reject (403)
Step 5   Contract marshaled for signing
Step 6   Dataset policy fetched from APD
           GET {APD_BASE_URL}/api/v1/policy/by-item/{datasetId}
           → 404  →  reject
Step 7   Unsigned contract stored to disk ({contractId}.bin + .json)
Step 8   Orchestrator signature computed and embedded in contract.signatures.*
Step 9   Signed contract stored to disk (overwrites step 7 files)
Step 10  Docker Compose URL resolved from backend
           GET {BACKEND_URL}/p3dx/apps/{appId}/compose-url
           Header: X-API-Key
Step 11  DeployEnclave called with contract + compose URL
Step 12  TEE started
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `8085` | HTTP listen port |
| `BACKEND_URL` | Yes | — | p3dx-aaa base URL |
| `BACKEND_API_KEY` | Yes | — | Shared key for backend callbacks |
| `APD_BASE_URL` | Yes | — | APD base URL |
| `STORE_PATH` | No | `./` | Directory for contract artifact files |
| `STORE_KEY` | No | dummy 32-byte key | Encryption key for binary storage |
| `ORCH_PRIVATE_KEY_PATH` | No | — | RSA private key for orchestrator signing; mock signature used if absent |
| `TEE_DEPLOY_DRY_RUN` | No | `true` | Skip real TEE deploy HTTP call |
| `TEE_DEPLOY_URL` | No | `http://localhost:8080/deployEnclave` | TEE deploy endpoint (used when `TEE_DEPLOY_DRY_RUN=false`) |
| `FORCE_TOKEN_MISMATCH` | No | — | Set to `true` to deliberately corrupt the fingerprint (testing only) |

---

## More Information

See the p3dx-aaa `Setup.md` for the full end-to-end workload flow and how TOP fits into the P3DX platform.
