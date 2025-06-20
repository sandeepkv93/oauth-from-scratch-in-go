package tests

import (
	"testing"

	"oauth-server/pkg/crypto"
)

func TestPKCECodeVerifierGeneration(t *testing.T) {
	pkce := crypto.NewPKCEManager()

	verifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		t.Errorf("Expected successful verifier generation, got error: %v", err)
	}

	if len(verifier) < 43 || len(verifier) > 128 {
		t.Errorf("Expected verifier length between 43-128, got %d", len(verifier))
	}

	if !pkce.IsValidCodeVerifier(verifier) {
		t.Error("Generated verifier should be valid")
	}
}

func TestPKCECodeChallengeGeneration(t *testing.T) {
	pkce := crypto.NewPKCEManager()

	verifier, _ := pkce.GenerateCodeVerifier()

	// Test plain method
	challenge, err := pkce.GenerateCodeChallenge(verifier, "plain")
	if err != nil {
		t.Errorf("Expected successful challenge generation (plain), got error: %v", err)
	}
	if challenge != verifier {
		t.Error("Plain challenge should equal verifier")
	}

	// Test S256 method
	challenge, err = pkce.GenerateCodeChallenge(verifier, "S256")
	if err != nil {
		t.Errorf("Expected successful challenge generation (S256), got error: %v", err)
	}
	if challenge == verifier {
		t.Error("S256 challenge should not equal verifier")
	}
	if len(challenge) == 0 {
		t.Error("S256 challenge should not be empty")
	}
}

func TestPKCEVerification(t *testing.T) {
	pkce := crypto.NewPKCEManager()

	verifier, _ := pkce.GenerateCodeVerifier()

	// Test plain method verification
	challenge, _ := pkce.GenerateCodeChallenge(verifier, "plain")
	err := pkce.VerifyCodeChallenge(verifier, challenge, "plain")
	if err != nil {
		t.Errorf("Expected successful verification (plain), got error: %v", err)
	}

	// Test S256 method verification
	challenge, _ = pkce.GenerateCodeChallenge(verifier, "S256")
	err = pkce.VerifyCodeChallenge(verifier, challenge, "S256")
	if err != nil {
		t.Errorf("Expected successful verification (S256), got error: %v", err)
	}

	// Test wrong verifier
	wrongVerifier, _ := pkce.GenerateCodeVerifier()
	err = pkce.VerifyCodeChallenge(wrongVerifier, challenge, "S256")
	if err == nil {
		t.Error("Expected verification to fail with wrong verifier")
	}
}

func TestPKCEInvalidInputs(t *testing.T) {
	pkce := crypto.NewPKCEManager()

	// Test invalid verifier
	if pkce.IsValidCodeVerifier("short") {
		t.Error("Short verifier should be invalid")
	}

	invalidVerifier := "short"
	_, err := pkce.GenerateCodeChallenge(invalidVerifier, "S256")
	if err == nil {
		t.Error("Expected error for invalid verifier")
	}

	// Test unsupported method
	verifier, _ := pkce.GenerateCodeVerifier()
	_, err = pkce.GenerateCodeChallenge(verifier, "unsupported")
	if err == nil {
		t.Error("Expected error for unsupported method")
	}
}

func TestPKCESupportedMethods(t *testing.T) {
	pkce := crypto.NewPKCEManager()

	if !pkce.IsSupportedMethod("plain") {
		t.Error("Plain method should be supported")
	}

	if !pkce.IsSupportedMethod("S256") {
		t.Error("S256 method should be supported")
	}

	if pkce.IsSupportedMethod("unsupported") {
		t.Error("Unsupported method should not be supported")
	}

	methods := pkce.GetSupportedMethods()
	if len(methods) != 2 {
		t.Errorf("Expected 2 supported methods, got %d", len(methods))
	}
}