package qulebanauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testAppID = "qlb_000102030405060708090a0b0c0d0e0f"
const testSecret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
const testUID = "TESTONLY-111"
const fixedIssued int64 = 1700000000

func testAuth() *QuLeBanAuth { return NewQuLeBanAuth(testAppID, testSecret) }
func claimsFor(kind string) jwt.MapClaims {
	return jwt.MapClaims{"app_id": testAppID, "uid": testUID, "token_type": kind, "iss": "quleban-auth", "aud": []string{audience(kind)},
		"iat": fixedIssued, "nbf": fixedIssued, "exp": fixedIssued + 7200, "jti": "AAECAwQFBgcICQoLDA0ODw"}
}
func signClaims(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func signJSON(header, payload string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	m := hmac.New(sha256.New, []byte(testSecret))
	m.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func TestPublicAPIRoundTrip(t *testing.T) {
	a := testAuth()
	for _, uid := range []string{"111", "玩家😀", strings.Repeat("a", 200)} {
		code := a.GetCodeByDefaultDuration(uid)
		if !code.IsSuccess || !a.VerifyCode(code.Code) || a.GetUidByCode(code.Code).Uid != uid {
			t.Fatalf("code roundtrip failed: %+v", code)
		}
		ss := a.GetSSTokenByDefaultDuration(uid)
		if !ss.IsSuccess || !a.VerifySSToken(ss.Token) || a.GetUidBySSToken(ss.Token).Uid != uid {
			t.Fatalf("token roundtrip failed: %+v", ss)
		}
		if a.VerifySSToken(code.Code) || a.VerifyCode(ss.Token) {
			t.Fatal("credential kinds must be isolated")
		}
		if a.GetCodeByDefaultDuration(uid).Code == code.Code {
			t.Fatal("each issued credential needs a fresh jti")
		}
	}
}

func TestDurationContract(t *testing.T) {
	a := testAuth()
	for _, duration := range []int64{-1, 0, 1, MinCodeDurationMillis, 3600123} {
		c := a.GetCode("111", duration)
		if !c.IsSuccess || c.ExpireDate%1000 != 0 {
			t.Fatalf("duration %d: %+v", duration, c)
		}
		parts := strings.Split(c.Code, ".")
		data, _ := decodeCanonical(parts[1])
		var raw map[string]json.RawMessage
		json.Unmarshal(data, &raw)
		var iat, exp int64
		json.Unmarshal(raw["iat"], &iat)
		json.Unmarshal(raw["exp"], &exp)
		want := duration
		if want < MinCodeDurationMillis {
			want = MinCodeDurationMillis
		}
		if exp-iat != want/1000 || c.ExpireDate != exp*1000 {
			t.Fatal("millisecond duration contract mismatch")
		}
	}
	s := a.GetSSToken("111", 1)
	if !s.IsSuccess || s.ExpireDate < time.Now().Add(2*time.Hour-time.Second).UnixMilli() {
		t.Fatal("SSToken floor must be 2 hours")
	}
	if a.GetCode("111", math.MaxInt64).IsSuccess {
		t.Fatal("overflowing lifetime accepted")
	}
}

func TestInvalidConfigurationAndUID(t *testing.T) {
	for _, a := range []*QuLeBanAuth{nil, {}, NewQuLeBanAuth("bad", testSecret), NewQuLeBanAuth(testAppID, "dev1_secret_key!"), NewQuLeBanAuth(testAppID, testSecret+"=")} {
		if a.GetCode("111", 1).IsSuccess || a.VerifyCode("a.b.c") {
			t.Fatal("invalid credentials accepted")
		}
	}
	for _, uid := range []string{"", " ", " 111", "111\n", strings.Repeat("中", 67), string([]byte{0xff})} {
		if testAuth().GetCode(uid, 1).IsSuccess {
			t.Fatal("invalid UID accepted")
		}
	}
}

func TestTokenValidation(t *testing.T) {
	now := time.Unix(fixedIssued+10, 0)
	cases := []struct {
		name   string
		mutate func(jwt.MapClaims)
		want   int
	}{
		{"app mismatch", func(c jwt.MapClaims) { c["app_id"] = "qlb_11111111111111111111111111111111" }, TokenInvalid},
		{"type mismatch", func(c jwt.MapClaims) { c["token_type"] = "ss_token" }, TokenInvalid},
		{"issuer mismatch", func(c jwt.MapClaims) { c["iss"] = "other" }, TokenInvalid},
		{"audience mismatch", func(c jwt.MapClaims) { c["aud"] = "other" }, TokenInvalid},
		{"multiple audiences", func(c jwt.MapClaims) { c["aud"] = []string{"quleban-code", "other"} }, TokenInvalid},
		{"missing expiration", func(c jwt.MapClaims) { delete(c, "exp") }, TokenInvalid},
		{"fractional date", func(c jwt.MapClaims) { c["exp"] = float64(fixedIssued) + 99.5 }, TokenInvalid},
		{"future issue", func(c jwt.MapClaims) { c["iat"] = fixedIssued + 20; c["nbf"] = fixedIssued + 20 }, TokenInvalid},
		{"not active", func(c jwt.MapClaims) { c["nbf"] = fixedIssued + 20 }, TokenInvalid},
		{"nbf before iat", func(c jwt.MapClaims) { c["nbf"] = fixedIssued - 1 }, TokenInvalid},
		{"exp equal nbf", func(c jwt.MapClaims) { c["exp"] = fixedIssued + 5; c["nbf"] = fixedIssued + 5 }, TokenInvalid},
		{"expired", func(c jwt.MapClaims) { c["exp"] = fixedIssued + 9 }, TokenExpired},
		{"expired wrong type", func(c jwt.MapClaims) { c["exp"] = fixedIssued + 9; c["token_type"] = "ss_token" }, TokenInvalid},
		{"missing id", func(c jwt.MapClaims) { delete(c, "jti") }, TokenInvalid},
		{"noncanonical id", func(c jwt.MapClaims) { c["jti"] = "AAECAwQFBgcICQoLDA0ODx" }, TokenInvalid},
		{"blank uid", func(c jwt.MapClaims) { c["uid"] = " " }, TokenInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := claimsFor("code")
			tc.mutate(c)
			r := testAuth().verifyAt(signClaims(t, c), "code", now)
			if r.SdkErrorCode != tc.want || r.Uid != "" {
				t.Fatalf("got %+v want %d", r, tc.want)
			}
		})
	}
	code := signClaims(t, claimsFor("code"))
	if !testAuth().verifyAt(code, "code", time.Unix(fixedIssued+7199, 999999999)).IsSuccess {
		t.Fatal("valid before expiry")
	}
	if testAuth().verifyAt(code, "code", time.Unix(fixedIssued+7200, 0)).SdkErrorCode != TokenExpired {
		t.Fatal("must expire at boundary")
	}
	other := NewQuLeBanAuth(testAppID, base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
	if other.verifyAt(code, "code", now).SdkErrorCode != TokenVerifyFailed {
		t.Fatal("wrong key accepted")
	}
	c := claimsFor("code")
	c["aud"] = "quleban-code"
	if !testAuth().verifyAt(signClaims(t, c), "code", now).IsSuccess {
		t.Fatal("string audience should interoperate")
	}
}

func TestStrictJWTEncoding(t *testing.T) {
	payload, _ := json.Marshal(claimsFor("code"))
	p := string(payload)
	header := `{"alg":"HS256","typ":"JWT"}`
	cases := []struct {
		name, header, payload string
		want                  int
	}{
		{"duplicate uid", header, strings.Replace(p, `"uid":"TESTONLY-111"`, `"uid":"evil","uid":"TESTONLY-111"`, 1), TokenDecodeFailed},
		{"nested duplicate", header, strings.TrimSuffix(p, "}") + `,"extra":{"a":1,"a":2}}`, TokenDecodeFailed},
		{"duplicate header", `{"alg":"HS256","alg":"HS256","typ":"JWT"}`, p, TokenDecodeFailed},
		{"isolated high surrogate", header, strings.Replace(p, `"TESTONLY-111"`, `"\ud800"`, 1), TokenDecodeFailed},
		{"isolated low surrogate", header, strings.Replace(p, `"TESTONLY-111"`, `"\udc00"`, 1), TokenDecodeFailed},
		{"wrong algorithm", `{"alg":"none","typ":"JWT"}`, p, TokenVerifyFailed},
		{"crit header", `{"alg":"HS256","typ":"JWT","crit":[]}`, p, TokenInvalid},
		{"b64 header", `{"alg":"HS256","typ":"JWT","b64":true}`, p, TokenInvalid},
		{"wrong typ", `{"alg":"HS256","typ":"other"}`, p, TokenInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testAuth().verifyAt(signJSON(tc.header, tc.payload), "code", time.Unix(fixedIssued+1, 0))
			if r.SdkErrorCode != tc.want {
				t.Fatalf("got %+v want %d", r, tc.want)
			}
		})
	}
	good := signJSON(header, p)
	for _, bad := range []string{good + "=", good[:20] + "\r\n" + good[20:], strings.Repeat("a", maxTokenBytes+1), "", "a.b.c"} {
		if testAuth().verifyAt(bad, "code", time.Unix(fixedIssued+1, 0)).IsSuccess {
			t.Fatal("noncanonical token accepted")
		}
	}
	paired := strings.Replace(p, `"TESTONLY-111"`, `"\ud83d\ude00"`, 1)
	if r := testAuth().verifyAt(signJSON(header, paired), "code", time.Unix(fixedIssued+1, 0)); !r.IsSuccess || r.Uid != "😀" {
		t.Fatalf("valid surrogate pair failed: %+v", r)
	}
}

func TestJSONDepthBoundary(t *testing.T) {
	base, _ := json.Marshal(claimsFor("code"))
	for _, arrays := range []int{15, 16} {
		payload := strings.TrimSuffix(string(base), "}") + `,"extra":` + strings.Repeat("[", arrays) + "0" + strings.Repeat("]", arrays) + "}"
		result := testAuth().verifyAt(signJSON(`{"alg":"HS256","typ":"JWT"}`, payload), "code", time.Unix(fixedIssued+1, 0))
		if result.IsSuccess != (arrays == 15) {
			t.Fatalf("root plus %d arrays has wrong depth handling: %+v", arrays, result)
		}
	}
}

func TestCreationIgnoresJWTGlobalPrecision(t *testing.T) {
	previous := jwt.TimePrecision
	jwt.TimePrecision = time.Millisecond
	defer func() { jwt.TimePrecision = previous }()
	result := testAuth().GetCodeByDefaultDuration("111")
	if !result.IsSuccess || !testAuth().VerifyCode(result.Code) {
		t.Fatal("another package's JWT precision must not affect our integer timestamp contract")
	}
}

type fixture struct {
	Notice    string `json:"notice"`
	AppID     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
	UID       string `json:"uid"`
	IssuedAt  int64  `json:"issued_at"`
	ExpiresAt int64  `json:"expires_at"`
	VerifyAt  int64  `json:"verify_at"`
	Code      string `json:"code"`
	SSToken   string `json:"ss_token"`
	Callback  struct {
		Path      string `json:"path"`
		Timestamp string `json:"timestamp"`
		Nonce     string `json:"nonce"`
		Body      string `json:"body"`
		Signature string `json:"signature"`
	} `json:"callback"`
}

func TestInteropFixture(t *testing.T) {
	f := fixture{Notice: "PUBLIC TEST-ONLY credentials. Never configure these in GM or production.", AppID: testAppID, AppSecret: testSecret, UID: testUID, IssuedAt: fixedIssued, ExpiresAt: fixedIssued + 7200, VerifyAt: fixedIssued + 10, Code: signClaims(t, claimsFor("code")), SSToken: signClaims(t, claimsFor("ss_token"))}
	f.Callback.Path = "/quleban/%E8%B5%84%E6%96%99"
	f.Callback.Timestamp = fmt.Sprint(f.VerifyAt * 1000)
	f.Callback.Nonce = "000102030405060708090a0b0c0d0e0f"
	f.Callback.Body = `{"code":"` + f.Code + `"}`
	f.Callback.Signature = requestSignature(testSecret, f.Callback.Path, testAppID, f.Callback.Timestamp, f.Callback.Nonce, []byte(f.Callback.Body))
	data, err := os.ReadFile("testdata/auth-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var got fixture
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != f.Code || got.SSToken != f.SSToken || got.Callback.Signature != f.Callback.Signature {
		t.Fatal("cross-language fixture drift")
	}
	if !testAuth().verifyAt(got.Code, "code", time.Unix(got.VerifyAt, 0)).IsSuccess || !testAuth().verifyAt(got.SSToken, "ss_token", time.Unix(got.VerifyAt, 0)).IsSuccess {
		t.Fatal("fixture tokens invalid")
	}
}

func TestStructAndConstructorInitialization(t *testing.T) {
	direct := &QuLeBanAuth{AppID: testAppID, AppSecret: testSecret}
	constructed := NewQuLeBanAuth(testAppID, testSecret)
	code := direct.GetCodeByDefaultDuration("111")
	if !code.IsSuccess || constructed.GetUidByCode(code.Code).Uid != "111" {
		t.Fatal("constructor must verify credentials issued by a directly initialized struct")
	}
	token := constructed.GetSSTokenByDefaultDuration("111")
	if !token.IsSuccess || direct.GetUidBySSToken(token.Token).Uid != "111" {
		t.Fatal("directly initialized struct must verify credentials issued by the constructor")
	}
}

func FuzzVerifyTokens(f *testing.F) {
	for _, s := range []string{"", "a.b.c", strings.Repeat("x", 17000), signJSON(`{"alg":"HS256","typ":"JWT"}`, `{"uid":"x"}`)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		a := testAuth()
		c := a.GetUidByCode(raw)
		s := a.GetUidBySSToken(raw)
		if !c.IsSuccess && c.Uid != "" || !s.IsSuccess && s.Uid != "" {
			t.Fatal("failed verification exposed UID")
		}
	})
}
