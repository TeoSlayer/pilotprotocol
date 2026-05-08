// SPDX-License-Identifier: AGPL-3.0-or-later

package registry

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- jwtAud UnmarshalJSON ------------------------------------------------

func TestJwtAudAcceptsStringAndSlice(t *testing.T) {
	var a jwtAud
	if err := a.UnmarshalJSON([]byte(`"one"`)); err != nil {
		t.Fatalf("string: %v", err)
	}
	if len(a) != 1 || a[0] != "one" {
		t.Fatalf("string result: %v", a)
	}

	var b jwtAud
	if err := b.UnmarshalJSON([]byte(`["a","b"]`)); err != nil {
		t.Fatalf("slice: %v", err)
	}
	if len(b) != 2 || b[0] != "a" || b[1] != "b" {
		t.Fatalf("slice result: %v", b)
	}
}

func TestJwtAudRejectsUnsupportedType(t *testing.T) {
	var a jwtAud
	if err := a.UnmarshalJSON([]byte(`123`)); err == nil {
		t.Fatalf("expected error on number aud")
	}
}

// --- decodeJWT ----------------------------------------------------------

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func makeJWT(t *testing.T, header, claims map[string]interface{}, signatureBytes []byte) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	return fmt.Sprintf("%s.%s.%s", b64url(h), b64url(c), b64url(signatureBytes))
}

func TestDecodeJWTRejectsWrongPartCount(t *testing.T) {
	for _, tok := range []string{"", "one", "one.two", "one.two.three.four"} {
		if _, _, _, err := decodeJWT(tok); err == nil {
			t.Fatalf("expected error for %q", tok)
		}
	}
}

func TestDecodeJWTRejectsBadBase64Header(t *testing.T) {
	tok := "!!!.eyJ9.sig"
	if _, _, _, err := decodeJWT(tok); err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("expected header decode error, got %v", err)
	}
}

func TestDecodeJWTRejectsBadJSONHeader(t *testing.T) {
	tok := b64url([]byte("not-json")) + "." + b64url([]byte(`{}`)) + "." + b64url([]byte("sig"))
	if _, _, _, err := decodeJWT(tok); err == nil || !strings.Contains(err.Error(), "parse JWT header") {
		t.Fatalf("expected header parse error, got %v", err)
	}
}

func TestDecodeJWTRejectsBadJSONClaims(t *testing.T) {
	tok := b64url([]byte(`{"alg":"HS256"}`)) + "." + b64url([]byte("not-json")) + "." + b64url([]byte("sig"))
	if _, _, _, err := decodeJWT(tok); err == nil || !strings.Contains(err.Error(), "parse JWT claims") {
		t.Fatalf("expected claims parse error, got %v", err)
	}
}

func TestDecodeJWTHappyPath(t *testing.T) {
	tok := makeJWT(t,
		map[string]interface{}{"alg": "HS256", "kid": "k1"},
		map[string]interface{}{"iss": "https://issuer", "sub": "user1", "aud": "aud1", "exp": 9999999999},
		[]byte("rawsig"))
	hdr, claims, signingInput, err := decodeJWT(tok)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if hdr.Alg != "HS256" || hdr.Kid != "k1" {
		t.Fatalf("header: %+v", hdr)
	}
	if claims.Issuer != "https://issuer" || claims.Subject != "user1" {
		t.Fatalf("claims: %+v", claims)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "aud1" {
		t.Fatalf("audience: %v", claims.Audience)
	}
	// signingInput is header+"."+claims parts.
	if strings.Count(signingInput, ".") != 1 {
		t.Fatalf("signingInput should have one dot: %q", signingInput)
	}
}

// --- verifyJWTSignatureHS256 -------------------------------------------

func TestVerifyHS256RejectsBadSignatureB64(t *testing.T) {
	if err := verifyJWTSignatureHS256("input", "!!!", []byte("secret")); err == nil {
		t.Fatalf("expected decode error")
	}
}

func TestVerifyHS256RejectsBadMAC(t *testing.T) {
	// Compute a valid HMAC with one secret, try to verify with another.
	mac := hmac.New(sha256.New, []byte("right"))
	mac.Write([]byte("input"))
	sig := b64url(mac.Sum(nil))
	if err := verifyJWTSignatureHS256("input", sig, []byte("wrong")); err == nil {
		t.Fatalf("expected HMAC mismatch")
	}
}

func TestVerifyHS256AcceptsGoodMAC(t *testing.T) {
	secret := []byte("topsecret")
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("input"))
	sig := b64url(mac.Sum(nil))
	if err := verifyJWTSignatureHS256("input", sig, secret); err != nil {
		t.Fatalf("valid HMAC: %v", err)
	}
}

// --- validateJWTClaims ------------------------------------------------

func TestValidateClaimsIssuerMismatch(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{Issuer: "a"}, "b", "")
	if err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("expected issuer mismatch: %v", err)
	}
}

func TestValidateClaimsAudienceMissing(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{Audience: jwtAud{"x", "y"}}, "", "z")
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience mismatch: %v", err)
	}
}

func TestValidateClaimsAudiencePresent(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{Audience: jwtAud{"x", "z"}}, "", "z")
	if err != nil {
		t.Fatalf("expected audience match: %v", err)
	}
}

func TestValidateClaimsExpiryPastSkew(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{Expiry: time.Now().Unix() - 3600}, "", "")
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired: %v", err)
	}
}

func TestValidateClaimsNotBeforeFuture(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{NotBefore: time.Now().Unix() + 3600}, "", "")
	if err == nil || !strings.Contains(err.Error(), "not yet valid") {
		t.Fatalf("expected nbf error: %v", err)
	}
}

func TestValidateClaimsHappyPath(t *testing.T) {
	err := validateJWTClaims(&jwtClaims{
		Issuer:    "iss",
		Audience:  jwtAud{"aud"},
		Expiry:    time.Now().Unix() + 3600,
		NotBefore: time.Now().Unix() - 3600,
	}, "iss", "aud")
	if err != nil {
		t.Fatalf("happy: %v", err)
	}
}

func TestValidateClaimsSkipsZeroExpiryAndNotBefore(t *testing.T) {
	// Zero values mean "not set" — should be accepted.
	if err := validateJWTClaims(&jwtClaims{}, "", ""); err != nil {
		t.Fatalf("zero claims should validate: %v", err)
	}
}

// --- JWKS cache ---------------------------------------------------------

func TestNewJWKSCacheTTL(t *testing.T) {
	c := newJWKSCache()
	if c.ttl != jwksCacheTTL {
		t.Fatalf("ttl: %v, want %v", c.ttl, jwksCacheTTL)
	}
	if len(c.keys) != 0 {
		t.Fatalf("keys should be empty")
	}
}

func TestJWKSCacheCachedSingleKeyNoKid(t *testing.T) {
	c := newJWKSCache()
	c.url = "https://idp/jwks"
	c.fetchedAt = time.Now()
	c.keys = []jwksKey{{Kid: "solo", Kty: "oct"}}
	key, err := c.getKey("https://idp/jwks", "")
	if err != nil {
		t.Fatalf("solo lookup: %v", err)
	}
	if key.Kid != "solo" {
		t.Fatalf("kid: %q", key.Kid)
	}
}

func TestJWKSCacheCachedMultiKeyNoKid(t *testing.T) {
	c := newJWKSCache()
	c.url = "https://idp/jwks"
	c.fetchedAt = time.Now()
	c.keys = []jwksKey{{Kid: "a"}, {Kid: "b"}}
	_, err := c.getKey("https://idp/jwks", "")
	if err == nil || !strings.Contains(err.Error(), "missing required 'kid'") {
		t.Fatalf("expected missing-kid error, got %v", err)
	}
}

func TestJWKSCacheCachedKidHitAndMiss(t *testing.T) {
	c := newJWKSCache()
	c.url = "https://idp/jwks"
	c.fetchedAt = time.Now()
	c.keys = []jwksKey{{Kid: "a"}, {Kid: "b"}}

	key, err := c.getKey("https://idp/jwks", "b")
	if err != nil || key.Kid != "b" {
		t.Fatalf("expected kid=b, got %v %v", key, err)
	}

	if _, err := c.getKey("https://idp/jwks", "nope"); err == nil || !strings.Contains(err.Error(), "not found (cached)") {
		t.Fatalf("expected cached-not-found: %v", err)
	}
}

func TestJWKSCacheFetchesOnCacheMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[{"kty":"oct","kid":"k1","k":"xxx"}]}`))
	}))
	defer srv.Close()

	c := newJWKSCache()
	key, err := c.getKey(srv.URL, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if key.Kid != "k1" {
		t.Fatalf("kid: %q", key.Kid)
	}
	if c.url != srv.URL || len(c.keys) != 1 {
		t.Fatalf("cache not populated: %+v", c.keys)
	}
}

func TestJWKSCacheFetchMultiNoKidErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[{"kid":"a"},{"kid":"b"}]}`))
	}))
	defer srv.Close()

	c := newJWKSCache()
	if _, err := c.getKey(srv.URL, ""); err == nil || !strings.Contains(err.Error(), "missing required 'kid'") {
		t.Fatalf("expected missing-kid error: %v", err)
	}
}

func TestJWKSCacheFetchKidNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"keys":[{"kid":"a"}]}`))
	}))
	defer srv.Close()

	c := newJWKSCache()
	if _, err := c.getKey(srv.URL, "b"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found: %v", err)
	}
}

// --- fetchJWKSKeys -----------------------------------------------------

func TestFetchJWKSKeysBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	_, err := fetchJWKSKeys(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected 500: %v", err)
	}
}

func TestFetchJWKSKeysBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("not-json"))
	}))
	defer srv.Close()
	_, err := fetchJWKSKeys(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "parse JWKS") {
		t.Fatalf("expected parse error: %v", err)
	}
}

func TestFetchJWKSKeysNetworkFail(t *testing.T) {
	_, err := fetchJWKSKeys("http://127.0.0.1:1") // refused immediately
	if err == nil || !strings.Contains(err.Error(), "fetch JWKS") {
		t.Fatalf("expected fetch error: %v", err)
	}
}

// --- verifyJWTSignatureRS256 ------------------------------------------

func rsaKeyFromPrivate(priv *rsa.PublicKey) *jwksKey {
	return &jwksKey{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes()),
	}
}

func TestVerifyRS256HappyAndBad(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	signingInput := "aaa.bbb"
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	jwkKey := rsaKeyFromPrivate(&priv.PublicKey)

	// Happy path.
	if err := verifyJWTSignatureRS256(signingInput, b64url(sig), jwkKey); err != nil {
		t.Fatalf("happy: %v", err)
	}

	// Bad sig.
	bad := make([]byte, len(sig))
	copy(bad, sig)
	bad[0] ^= 0xff
	if err := verifyJWTSignatureRS256(signingInput, b64url(bad), jwkKey); err == nil {
		t.Fatalf("expected bad-sig error")
	}

	// Bad N b64.
	badKey := *jwkKey
	badKey.N = "!!!"
	if err := verifyJWTSignatureRS256(signingInput, b64url(sig), &badKey); err == nil || !strings.Contains(err.Error(), "decode RSA n") {
		t.Fatalf("expected decode n error: %v", err)
	}

	// Bad E b64.
	badKey2 := *jwkKey
	badKey2.E = "!!!"
	if err := verifyJWTSignatureRS256(signingInput, b64url(sig), &badKey2); err == nil || !strings.Contains(err.Error(), "decode RSA e") {
		t.Fatalf("expected decode e error: %v", err)
	}

	// Bad signature b64.
	if err := verifyJWTSignatureRS256(signingInput, "!!!", jwkKey); err == nil {
		t.Fatalf("expected decode-sig error")
	}
}
