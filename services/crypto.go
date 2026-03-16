package services

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
)

func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, nil // No path provided, return gracefully
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil // Not a PEM block
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func Sign(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(data)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hash[:])
}

func Verify(data, sig []byte, pub *rsa.PublicKey) error {
	hash := sha256.Sum256(data)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig)
}
