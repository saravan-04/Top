package contract

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// canonicalBytes marshals the contract with an empty Signatures field so that
// the hash covers the contract content only, not the signatures themselves.
func canonicalBytes(c Contract) ([]byte, error) {
	tmp := c
	tmp.Signatures = Signatures{}
	return json.Marshal(tmp)
}

// ComputeHash computes a SHA-256 hash of the contract's canonical form.
// Returns the hash as a "sha256:<hex>" string, the raw hash bytes, and any error.
func ComputeHash(c Contract) (string, []byte, error) {
	b, err := canonicalBytes(c)
	if err != nil {
		return "", nil, err
	}

	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), sum[:], nil
}

// SignWithKeycloakSession produces a consumer HMAC-SHA256 signature and populates
// the contract's Signatures fields. The message signed is:
//
//	{contractHashHex}|{userID}|{sessionID}|{issuedAt}
//
// The signature is stored as base64 in contract.signatures.consumer_signature.
func SignWithKeycloakSession(c *Contract, claims KCClaims, serverSecret []byte) error {
	hashString, hashBytes, err := ComputeHash(*c)
	if err != nil {
		return fmt.Errorf("contract hash failed: %w", err)
	}

	msg := fmt.Sprintf(
		"%x|%s|%s|%d",
		hashBytes,
		claims.UserID,
		claims.SessionID,
		claims.IssuedAt,
	)

	h := hmac.New(sha256.New, serverSecret)
	h.Write([]byte(msg))
	signature := h.Sum(nil)

	now := time.Now().UTC()

	c.Signatures.ContractHash = hashString
	c.Signatures.SignatureAlgorithm = "KEYCLOAK_SESSION_HMAC_SHA256"
	c.Signatures.ConsumerSignature = base64.StdEncoding.EncodeToString(signature)
	c.Signatures.SignedAt.Consumer = &now

	return nil
}
