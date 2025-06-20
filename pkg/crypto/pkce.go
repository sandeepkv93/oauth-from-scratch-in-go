package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidCodeVerifier   = errors.New("invalid code verifier")
	ErrInvalidCodeChallenge  = errors.New("invalid code challenge")
	ErrCodeChallengeMismatch = errors.New("code challenge verification failed")
)

type PKCEManager struct{}

func NewPKCEManager() *PKCEManager {
	return &PKCEManager{}
}

func (p *PKCEManager) GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	verifier := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(bytes)
	return verifier, nil
}

func (p *PKCEManager) GenerateCodeChallenge(verifier string, method string) (string, error) {
	if !p.IsValidCodeVerifier(verifier) {
		return "", ErrInvalidCodeVerifier
	}

	switch method {
	case "plain":
		return verifier, nil
	case "S256":
		hash := sha256.Sum256([]byte(verifier))
		challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
		return challenge, nil
	default:
		return "", ErrInvalidCodeChallenge
	}
}

func (p *PKCEManager) VerifyCodeChallenge(verifier, challenge, method string) error {
	if !p.IsValidCodeVerifier(verifier) {
		return ErrInvalidCodeVerifier
	}

	expectedChallenge, err := p.GenerateCodeChallenge(verifier, method)
	if err != nil {
		return err
	}

	if expectedChallenge != challenge {
		return ErrCodeChallengeMismatch
	}

	return nil
}

func (p *PKCEManager) IsValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	for _, char := range verifier {
		if !p.isUnreservedChar(char) {
			return false
		}
	}

	return true
}

func (p *PKCEManager) IsValidCodeChallenge(challenge string) bool {
	if len(challenge) < 43 || len(challenge) > 128 {
		return false
	}

	for _, char := range challenge {
		if !p.isUnreservedChar(char) {
			return false
		}
	}

	return true
}

func (p *PKCEManager) isUnreservedChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '.' || char == '_' || char == '~'
}

func (p *PKCEManager) IsSupportedMethod(method string) bool {
	return method == "plain" || method == "S256"
}

func (p *PKCEManager) GetSupportedMethods() []string {
	return []string{"plain", "S256"}
}