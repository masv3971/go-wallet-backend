package engine

import (
	"fmt"
	"time"

	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/websocket"
	"go.uber.org/zap/zapcore"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const secretSeedA = "d41d8cd98f00b204e9800998ecf8427e"
const secretSeedB = "0cc175b9c0f1b6a831c399e269772661"

// Deliberately awkward spellings: integer, 1.50, 2.0, big int, nested object
// and array, null, unknown members; whitespace is insignificant.
const fidelityMD = `{"org.siros.secret_seed":{"ns1":"` + secretSeedA + `","ns2":"` + secretSeedB + `"},` +
	`"org.example.ext":{"n":1.50,"m":2.0,"big":12345678901234567890,"arr":[1,{"z":null}],"s":"x"},"alg":"ES256","count":7}`

func bodyWithMD(md string) string {
	return `{"credentials":[{"credential":"c0"},{"credential":"c1"}],"credential_metadata":` + md + `}`
}

func parseResp(t *testing.T, body string) *CredentialResponse {
	t.Helper()
	var r CredentialResponse
	require.NoError(t, json.Unmarshal([]byte(body), &r))
	return &r
}

func TestCredentialMetadataRelay_VerbatimUnknownMembersAndSpelling(t *testing.T) {
	spaced := strings.NewReplacer(",", " ,\n ", ":", " : ").Replace(fidelityMD)
	relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(spaced)))
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata), "members, order, number spelling preserved; only whitespace removed")
	assert.False(t, relay.Encrypted)
}

func TestCredentialMetadataRelay_Absent(t *testing.T) {
	relay, err := credentialMetadataRelay(parseResp(t, `{"credentials":[{"credential":"c"}]}`))
	require.NoError(t, err)
	assert.Nil(t, relay)
	relay, err = credentialMetadataRelay(nil)
	require.NoError(t, err)
	assert.Nil(t, relay)
}

func TestCredentialMetadataRelay_ValidShapes(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxCredentialMetadataDepth) + `1` + strings.Repeat(`}`, maxCredentialMetadataDepth)
	var many []string
	for i := 0; i < maxCredentialMetadataMembers; i++ {
		many = append(many, fmt.Sprintf(`"k%d":%d`, i, i))
	}
	for name, md := range map[string]string{
		"empty object":             `{}`,
		"only unknown":             `{"org.example.x":{"a":[1,2,3]}}`,
		"max depth":                deep,
		"max members":              `{` + strings.Join(many, ",") + `}`,
		"max key length":           `{"` + strings.Repeat("k", maxCredentialMetadataKeyLen) + `":1}`,
		"max seed hex":             `{"org.siros.secret_seed":{"n":"` + strings.Repeat("ab", maxSecretSeedHexLen/2) + `"}}`,
		"same key in separate obj": `{"a":{"x":1},"b":{"x":2}}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := credentialMetadataRelay(parseResp(t, bodyWithMD(md)))
			require.NoError(t, err)
		})
	}
}

func TestCredentialMetadataRelay_Malformed(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxCredentialMetadataDepth+1) + `1` + strings.Repeat(`}`, maxCredentialMetadataDepth+1)
	deepArr := `{"a":` + strings.Repeat(`[`, maxCredentialMetadataDepth) + strings.Repeat(`]`, maxCredentialMetadataDepth) + `}`
	var many, manyNested []string
	for i := 0; i <= maxCredentialMetadataMembers; i++ {
		many = append(many, fmt.Sprintf(`"k%d":"`+secretSeedA+`"`, i))
		manyNested = append(manyNested, fmt.Sprintf(`"k%d":1`, i))
	}
	cases := map[string]string{
		"array":                 `[{"org.siros.secret_seed":{"n":"` + secretSeedA + `"}}]`,
		"string":                `"` + secretSeedA + `"`,
		"number":                `7`,
		"null":                  `null`,
		"legacy entry array":    `[{"type":"org.siros.NS.secret_seed","value":"` + secretSeedA + `"}]`,
		"too many members":      `{` + strings.Join(many, ",") + `}`,
		"too many nested":       `{"x":{` + strings.Join(manyNested, ",") + `}}`,
		"too deep objects":      deep,
		"too deep arrays":       deepArr,
		"key too long":          `{"` + strings.Repeat("k", maxCredentialMetadataKeyLen+1) + `":"` + secretSeedA + `"}`,
		"nested key too long":   `{"x":{"` + strings.Repeat("k", maxCredentialMetadataKeyLen+1) + `":1}}`,
		"too big":               `{"x":"` + strings.Repeat("p", maxCredentialMetadataBytes) + `"}`,
		"duplicate top key":     `{"x":1,"x":2}`,
		"duplicate seed key":    `{"org.siros.secret_seed":{"n":"` + secretSeedA + `","n":"` + secretSeedB + `"}}`,
		"duplicate seed member": `{"org.siros.secret_seed":{"n":"` + secretSeedA + `"},"org.siros.secret_seed":{"n":"` + secretSeedB + `"}}`,
		"seed not object":       `{"org.siros.secret_seed":"` + secretSeedA + `"}`,
		"seed array":            `{"org.siros.secret_seed":["` + secretSeedA + `"]}`,
		"seed empty":            `{"org.siros.secret_seed":{}}`,
		"seed null":             `{"org.siros.secret_seed":null}`,
		"seed non-string":       `{"org.siros.secret_seed":{"n":7}}`,
		"seed empty ns":         `{"org.siros.secret_seed":{"":"` + secretSeedA + `"}}`,
		"seed empty value":      `{"org.siros.secret_seed":{"n":""}}`,
		"seed uppercase hex":    `{"org.siros.secret_seed":{"n":"` + strings.ToUpper(secretSeedA) + `"}}`,
		"seed odd length":       `{"org.siros.secret_seed":{"n":"` + secretSeedA + `a"}}`,
		"seed non hex":          `{"org.siros.secret_seed":{"n":"` + secretSeedA[:30] + `zz"}}`,
		"seed too long":         `{"org.siros.secret_seed":{"n":"` + strings.Repeat("ab", maxSecretSeedHexLen/2+1) + `"}}`,
	}
	for name, md := range cases {
		t.Run(name, func(t *testing.T) {
			relay, err := credentialMetadataRelay(parseResp(t, bodyWithMD(md)))
			require.Error(t, err)
			assert.Nil(t, relay)
			for _, secret := range []string{secretSeedA, secretSeedB, strings.ToUpper(secretSeedA)} {
				assert.NotContains(t, err.Error(), secret, "errors must not leak values")
			}
		})
	}
}

// buildCredentialResults no longer carries any metadata: it applies to the
// whole response and travels on the flow-complete message.
func TestBuildCredentialResults_DoesNotCarryCredentialMetadata(t *testing.T) {
	h := &OID4VCIHandler{}
	res := h.buildCredentialResults(context.Background(), parseResp(t, bodyWithMD(fidelityMD)), &CredentialConfig{Format: "mso_mdoc"}, nil)
	require.Len(t, res, 2)
	wire, err := json.Marshal(res)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "credential_metadata")
	assert.NotContains(t, string(wire), secretSeedA)
}

// captureHandler returns a handler whose session echoes every sent message to
// the returned channel.
func captureHandler(t *testing.T) (*OID4VCIHandler, chan map[string]json.RawMessage, func()) {
	t.Helper()
	msgs := make(chan map[string]json.RawMessage, 8)
	conn, cleanup := wsTestServer(t, func(srvConn *websocket.Conn) {
		defer srvConn.Close()
		for {
			_, data, err := srvConn.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]json.RawMessage
			if json.Unmarshal(data, &m) == nil {
				msgs <- m
			}
		}
	})
	session := testSession(conn)
	flow := &Flow{ID: "f1", Session: session, Data: map[string]interface{}{}}
	h := &OID4VCIHandler{clientAuthMode: clientAuthLegacy, legacyAttestationRequested: true}
	h.BaseHandler = BaseHandler{Flow: flow, Logger: zap.NewNop()}
	return h, msgs, cleanup
}

func nextMsg(t *testing.T, ch chan map[string]json.RawMessage) map[string]json.RawMessage {
	t.Helper()
	select {
	case m := <-ch:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no message sent: flow hung")
		return nil
	}
}

func TestFinishIssuance_RelaysCredentialMetadataOnFlowComplete(t *testing.T) {
	for _, step := range []FlowStep{StepRequestingCredential, StepDeferred} {
		for _, enc := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/encrypted=%v", step, enc), func(t *testing.T) {
				h, ch, cleanup := captureHandler(t)
				defer cleanup()
				resp := parseResp(t, bodyWithMD(fidelityMD))
				resp.Encrypted = enc
				require.NoError(t, h.finishIssuance(context.Background(), step, resp, &CredentialConfig{Format: "mso_mdoc"}, nil, nil, &TokenResponse{}))
				m := nextMsg(t, ch)
				assert.JSONEq(t, `"flow_complete"`, string(m["type"]))
				assert.Equal(t, fidelityMD, string(m["credential_metadata"]), "object relayed verbatim at top level")
				_, hasFlag := m["credential_metadata_encrypted_response"]
				assert.Equal(t, enc, hasFlag)
				if enc {
					assert.JSONEq(t, `true`, string(m["credential_metadata_encrypted_response"]))
				}
				var creds []map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(m["credentials"], &creds))
				require.Len(t, creds, 2)
				for _, c := range creds {
					_, per := c["credential_metadata"]
					assert.False(t, per, "no per-credential credential_metadata")
				}
			})
		}
	}
}

func TestFinishIssuance_AbsentMetadataOmitsFields(t *testing.T) {
	h, ch, cleanup := captureHandler(t)
	defer cleanup()
	resp := parseResp(t, `{"credentials":[{"credential":"c"}]}`)
	resp.Encrypted = true
	require.NoError(t, h.finishIssuance(context.Background(), StepRequestingCredential, resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{}))
	m := nextMsg(t, ch)
	_, a := m["credential_metadata"]
	_, b := m["credential_metadata_encrypted_response"]
	assert.False(t, a)
	assert.False(t, b)
}

func TestFinishIssuance_MalformedFailsCleanly(t *testing.T) {
	for _, step := range []FlowStep{StepRequestingCredential, StepDeferred} {
		t.Run(string(step), func(t *testing.T) {
			h, ch, cleanup := captureHandler(t)
			defer cleanup()
			resp := parseResp(t, bodyWithMD(`{"org.siros.secret_seed":{"n":"NOT-HEX-`+secretSeedA+`"}}`))
			err := h.finishIssuance(context.Background(), step, resp, &CredentialConfig{Format: "x"}, nil, nil, &TokenResponse{})
			require.Error(t, err)
			m := nextMsg(t, ch)
			assert.JSONEq(t, `"flow_error"`, string(m["type"]))
			assert.Contains(t, string(m["error"]), string(ErrCodeCredentialError))
			assert.NotContains(t, string(m["error"]), secretSeedA)
			select {
			case extra := <-ch:
				t.Fatalf("unexpected extra message %s", extra["type"])
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

func TestFlowCompleteMessage_Redacted(t *testing.T) {
	m := FlowCompleteMessage{
		Credentials:                         []CredentialResult{{Credential: "c"}},
		CredentialMetadata:                  json.RawMessage(fidelityMD),
		CredentialMetadataEncryptedResponse: true,
	}
	r := m.Redacted()
	wire, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotContains(t, string(wire), "credential_metadata")
	assert.NotContains(t, string(wire), secretSeedA)
	assert.Contains(t, string(wire), `"credential":"c"`)
	assert.NotNil(t, m.CredentialMetadata, "original untouched")
}

func encryptedCredServer(t *testing.T, body CredentialResponse) *httptest.Server {
	t.Helper()
	pt, err := json.Marshal(body)
	require.NoError(t, err)
	return encryptedRawServer(t, string(pt))
}

// encryptedRawServer JWE-encrypts the given raw JSON body for the requester's key.
func encryptedRawServer(t *testing.T, raw string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		enc, ok := reqBody["credential_response_encryption"].(map[string]interface{})
		require.True(t, ok)
		jwk := enc["jwk"].(map[string]interface{})
		xb, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
		yb, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		pt := []byte(raw)
		encr, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, nil)
		require.NoError(t, err)
		jwe, err := encr.Encrypt(pt)
		require.NoError(t, err)
		s, _ := jwe.CompactSerialize()
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(s))
	}))
}

func issuerEnc(srvURL string) *IssuerMetadata {
	return &IssuerMetadata{CredentialEndpoint: srvURL, CredentialResponseEncryption: &CredentialResponseEncryptionConfig{
		AlgValuesSupported: []string{"ECDH-ES"}, EncValuesSupported: []string{"A128GCM"}, EncryptionRequired: true,
	}}
}

func TestRequestCredential_CredentialMetadata_JWEAndPlainFlag(t *testing.T) {
	body := bodyWithMD(fidelityMD)
	tok := &TokenResponse{AccessToken: "t", TokenType: "Bearer"}
	cfg := &CredentialConfig{Format: "mso_mdoc"}

	srv := encryptedRawServer(t, body)
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	resp, err := h.requestCredential(context.Background(), issuerEnc(srv.URL), tok, "", cfg, nil)
	require.NoError(t, err)
	relay, err := credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.True(t, relay.Encrypted)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer plain.Close()
	h2, cleanup2 := testOID4VCIHandler(t, plain.Client())
	defer cleanup2()
	resp, err = h2.requestCredential(context.Background(), &IssuerMetadata{CredentialEndpoint: plain.URL}, tok, "", cfg, nil)
	require.NoError(t, err)
	relay, err = credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.False(t, relay.Encrypted)
}

func TestPollDeferredCredential_CredentialMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("deferred polling waits one 5s interval")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(bodyWithMD(fidelityMD)))
	}))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	resp, err := h.pollDeferredCredential(context.Background(), &IssuerMetadata{CredentialIssuer: srv.URL}, &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "tx1")
	require.NoError(t, err)
	relay, err := credentialMetadataRelay(resp)
	require.NoError(t, err)
	require.NotNil(t, relay)
	assert.Equal(t, fidelityMD, string(relay.Metadata))
	assert.False(t, relay.Encrypted, "deferred responses are never JWE-decrypted")
}

// The values must not reach the logs on the issuance request path, at any level.
func TestRequestCredential_CredentialMetadata_NotLogged(t *testing.T) {
	core, logs := observer.New(zap.DebugLevel)
	srv := encryptedRawServer(t, bodyWithMD(fidelityMD))
	defer srv.Close()
	h, cleanup := testOID4VCIHandler(t, srv.Client())
	defer cleanup()
	h.Logger = zap.New(core)
	cfg := &CredentialConfig{Format: "mso_mdoc"}
	resp, err := h.requestCredential(context.Background(), issuerEnc(srv.URL), &TokenResponse{AccessToken: "t", TokenType: "Bearer"}, "", cfg, nil)
	require.NoError(t, err)
	_, err = credentialMetadataRelay(resp)
	require.NoError(t, err)
	// Malformed variant through the full finish path (logs a warning).
	h.Flow.Session.notifications = nil
	bad := parseResp(t, bodyWithMD(`{"EXTRA-SECRET-MEMBER":"EXTRA-SECRET-MEMBER","org.siros.secret_seed":{"n":"`+strings.ToUpper(secretSeedB)+`"}}`))
	require.Error(t, h.finishIssuance(context.Background(), StepRequestingCredential, bad, cfg, nil, nil, &TokenResponse{}))

	require.NotEmpty(t, logs.All())
	for _, e := range logs.All() {
		dump := e.Message
		for _, f := range e.Context {
			dump += " " + f.Key + "=" + f.String
			if f.Interface != nil {
				b, _ := json.Marshal(f.Interface)
				dump += string(b)
			}
			if f.Type == zapcore.ErrorType && f.Interface != nil {
				dump += f.Interface.(error).Error()
			}
		}
		for _, secret := range []string{secretSeedA, secretSeedB, strings.ToUpper(secretSeedB), "EXTRA-SECRET-MEMBER"} {
			assert.NotContains(t, dump, secret)
		}
	}
}

// Source scan: the only log lines in oid4vci.go allowed to print a raw
// response body are the known error-status branches (issuer error responses,
// never a 200 credential response). Anything new must be reviewed against
// credential_metadata secrecy.
func TestOID4VCISource_NoResponseBodyLoggedOnSuccessPath(t *testing.T) {
	src, err := os.ReadFile("oid4vci.go")
	require.NoError(t, err)
	logLine := regexp.MustCompile(`Logger\.(Debug|Info|Warn|Error)\(`)
	bodyRef := regexp.MustCompile(`string\(body\)|credResp\b|deferredResp\b|resp\.Credential|zap\.Any\(|credential\)|results\b`)
	allowed := map[string]bool{
		`credential endpoint error`:           true,
		`PAR endpoint error`:                  true,
		`Unexpected deferred response status`: true,
	}
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		if !logLine.MatchString(l) {
			continue
		}
		stmt := l
		for j := i + 1; strings.Count(stmt, "(") != strings.Count(stmt, ")") && j < len(lines); j++ {
			stmt += " " + lines[j]
		}
		if bodyRef.MatchString(stmt) {
			ok := false
			for k := range allowed {
				if strings.Contains(stmt, k) {
					ok = true
				}
			}
			if strings.Contains(stmt, `endpoint error", zap.Int("status"`) {
				ok = true // generic logContext+" endpoint error"
			}
			assert.True(t, ok, "oid4vci.go:%d logs a response body: %s", i+1, strings.TrimSpace(l))
		}
	}
}
