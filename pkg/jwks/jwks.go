package jwks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type KeyManager struct {
	keys       map[string]*RSAKey
	currentKID string
}

type RSAKey struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
	Use        string
	Algorithm  string
}

type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use"`
	KeyID     string `json:"kid"`
	Algorithm string `json:"alg"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func NewKeyManager() (*KeyManager, error) {
	km := &KeyManager{
		keys: make(map[string]*RSAKey),
	}
	
	if err := km.generateNewKey(); err != nil {
		return nil, err
	}
	
	return km, nil
}

func (km *KeyManager) generateNewKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	keyID := uuid.New().String()
	
	key := &RSAKey{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		Use:        "sig",
		Algorithm:  "RS256",
	}
	
	km.keys[keyID] = key
	km.currentKID = keyID
	
	return nil
}

func (km *KeyManager) GetCurrentKey() *RSAKey {
	if km.currentKID == "" {
		return nil
	}
	return km.keys[km.currentKID]
}

func (km *KeyManager) GetKey(keyID string) *RSAKey {
	return km.keys[keyID]
}

func (km *KeyManager) GetJWKSet() *JWKSet {
	jwks := &JWKSet{
		Keys: make([]JWK, 0, len(km.keys)),
	}
	
	for _, key := range km.keys {
		jwk := JWK{
			KeyType:   "RSA",
			Use:       key.Use,
			KeyID:     key.ID,
			Algorithm: key.Algorithm,
			N:         base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			E:         base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	
	return jwks
}

func (km *KeyManager) SignToken(token *jwt.Token) (string, error) {
	currentKey := km.GetCurrentKey()
	if currentKey == nil {
		return "", errors.New("no signing key available")
	}
	
	token.Header["kid"] = currentKey.ID
	return token.SignedString(currentKey.PrivateKey)
}

func (km *KeyManager) VerifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		keyID, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("token missing kid header")
		}
		
		key := km.GetKey(keyID)
		if key == nil {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		
		return key.PublicKey, nil
	})
	
	return token, err
}

func (km *KeyManager) RotateKeys() error {
	return km.generateNewKey()
}

func (km *KeyManager) GetPrivateKeyPEM() (string, error) {
	currentKey := km.GetCurrentKey()
	if currentKey == nil {
		return "", errors.New("no current key available")
	}
	
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(currentKey.PrivateKey)
	if err != nil {
		return "", err
	}
	
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	return string(privateKeyPEM), nil
}

func (km *KeyManager) GetPublicKeyPEM() (string, error) {
	currentKey := km.GetCurrentKey()
	if currentKey == nil {
		return "", errors.New("no current key available")
	}
	
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(currentKey.PublicKey)
	if err != nil {
		return "", err
	}
	
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	return string(publicKeyPEM), nil
}

func (km *KeyManager) SerializeJWKSet() ([]byte, error) {
	jwkSet := km.GetJWKSet()
	return json.Marshal(jwkSet)
}

func (km *KeyManager) GetCurrentKeyID() string {
	return km.currentKID
}