// Package qulebanauth signs and verifies QuLeBan host authentication tokens.
// It performs no network requests and needs no hall server address.
package qulebanauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
)

const (
	TokenSuccess                   = 0
	TokenCreateFailed              = 1001
	TokenVerifyFailed              = 1002
	TokenDecodeFailed              = 1003
	TokenInvalid                   = 1004
	TokenExpired                   = 1005
	TokenUnknown                   = 9999
	DefaultDurationMillis    int64 = 2 * 60 * 60 * 1000
	MinCodeDurationMillis    int64 = 30 * 60 * 1000
	MinSSTokenDurationMillis int64 = DefaultDurationMillis
	maxTokenBytes                  = 16 * 1024
)

// QuLeBanAuth is initialized with credentials copied from the GM console.
// Do not change its fields concurrently with calls to its methods.
type QuLeBanAuth struct {
	AppID     string
	AppSecret string
}

type QuLeBanCode struct {
	Code         string `json:"code"`
	ExpireDate   int64  `json:"expireDate"`
	IsSuccess    bool   `json:"isSuccess"`
	SdkErrorCode int    `json:"sdkErrorCode"`
}

type QuLeBanSSToken struct {
	Token        string `json:"token"`
	ExpireDate   int64  `json:"expireDate"`
	IsSuccess    bool   `json:"isSuccess"`
	SdkErrorCode int    `json:"sdkErrorCode"`
}

type QuLeBanUid struct {
	Uid          string `json:"uid"`
	IsSuccess    bool   `json:"isSuccess"`
	SdkErrorCode int    `json:"sdkErrorCode"`
}

type authClaims struct {
	AppID     string `json:"app_id"`
	UID       string `json:"uid"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func NewQuLeBanAuth(appID string, appSecret string) *QuLeBanAuth {
	return &QuLeBanAuth{AppID: appID, AppSecret: appSecret}
}

// expireDuration is in milliseconds, NOT time.Duration/nanoseconds.
func (a *QuLeBanAuth) GetCode(uid string, expireDuration int64) *QuLeBanCode {
	token, expires, code := a.create(uid, expireDuration, "code")
	return &QuLeBanCode{Code: token, ExpireDate: expires, IsSuccess: code == 0, SdkErrorCode: code}
}

func (a *QuLeBanAuth) GetCodeByDefaultDuration(uid string) *QuLeBanCode {
	return a.GetCode(uid, DefaultDurationMillis)
}

func (a *QuLeBanAuth) GetSSToken(uid string, expireDuration int64) *QuLeBanSSToken {
	token, expires, code := a.create(uid, expireDuration, "ss_token")
	return &QuLeBanSSToken{Token: token, ExpireDate: expires, IsSuccess: code == 0, SdkErrorCode: code}
}

func (a *QuLeBanAuth) GetSSTokenByDefaultDuration(uid string) *QuLeBanSSToken {
	return a.GetSSToken(uid, DefaultDurationMillis)
}

func (a *QuLeBanAuth) GetUidByCode(code string) *QuLeBanUid {
	return a.verify(code, "code")
}

func (a *QuLeBanAuth) GetUidBySSToken(ssToken string) *QuLeBanUid {
	return a.verify(ssToken, "ss_token")
}

func (a *QuLeBanAuth) VerifyCode(code string) bool    { return a.GetUidByCode(code).IsSuccess }
func (a *QuLeBanAuth) VerifySSToken(code string) bool { return a.GetUidBySSToken(code).IsSuccess }

func (a *QuLeBanAuth) validCredentials() bool {
	if a == nil || len(a.AppID) != 36 || !strings.HasPrefix(a.AppID, "qlb_") {
		return false
	}
	id, err := hex.DecodeString(a.AppID[4:])
	if err != nil || len(id) != 16 || strings.ToLower(a.AppID) != a.AppID {
		return false
	}
	key, err := base64.RawURLEncoding.Strict().DecodeString(a.AppSecret)
	return err == nil && len(key) == 32 && len(a.AppSecret) == 43
}

func validUID(uid string) bool {
	return uid != "" && strings.TrimSpace(uid) == uid && len(uid) <= 200 && utf8.ValidString(uid)
}

func audience(kind string) string {
	if kind == "code" {
		return "quleban-code"
	}
	return "quleban-server"
}

func (a *QuLeBanAuth) create(uid string, duration int64, kind string) (string, int64, int) {
	if !a.validCredentials() || !validUID(uid) {
		return "", 0, TokenInvalid
	}
	minimum := MinCodeDurationMillis
	if kind == "ss_token" {
		minimum = MinSSTokenDurationMillis
	}
	if duration < minimum {
		duration = minimum
	}
	now := time.Now().UTC().Truncate(time.Second)
	// Avoid time.Duration multiplication overflow; limit expiration to year 9999.
	seconds := duration / 1000
	if seconds > 253402300799-now.Unix() {
		return "", 0, TokenInvalid
	}
	expires := time.Unix(now.Unix()+seconds, 0)
	random := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "", 0, TokenCreateFailed
	}
	// Integer claims keep wire precision stable even if another package changes
	// the JWT library's global TimePrecision setting.
	claims := jwt.MapClaims{
		"app_id": a.AppID, "uid": uid, "token_type": kind,
		"iss": "quleban-auth", "aud": []string{audience(kind)},
		"iat": now.Unix(), "nbf": now.Unix(), "exp": expires.Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(random),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(a.AppSecret))
	if err != nil {
		return "", 0, TokenCreateFailed
	}
	return token, expires.Unix() * 1000, TokenSuccess
}

func failed(code int) *QuLeBanUid { return &QuLeBanUid{SdkErrorCode: code} }

func (a *QuLeBanAuth) verify(raw string, kind string) *QuLeBanUid {
	return a.verifyAt(raw, kind, time.Now())
}

func (a *QuLeBanAuth) verifyAt(raw string, kind string, now time.Time) *QuLeBanUid {
	if !a.validCredentials() {
		return failed(TokenInvalid)
	}
	if len(raw) > maxTokenBytes {
		return failed(TokenDecodeFailed)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return failed(TokenDecodeFailed)
	}
	var header map[string]json.RawMessage
	var payload map[string]json.RawMessage
	for i, dst := range []*map[string]json.RawMessage{&header, &payload} {
		decoded, err := decodeCanonical(parts[i])
		if err != nil || !utf8.Valid(decoded) || !uniqueJSON(decoded) || json.Unmarshal(decoded, dst) != nil || *dst == nil {
			return failed(TokenDecodeFailed)
		}
	}
	var alg, typ string
	if json.Unmarshal(header["alg"], &alg) != nil || alg != "HS256" {
		return failed(TokenVerifyFailed)
	}
	if json.Unmarshal(header["typ"], &typ) != nil || typ != "JWT" {
		return failed(TokenInvalid)
	}
	if _, exists := header["crit"]; exists {
		return failed(TokenInvalid)
	}
	if _, exists := header["b64"]; exists {
		return failed(TokenInvalid)
	}
	sig, err := decodeCanonical(parts[2])
	if err != nil {
		return failed(TokenDecodeFailed)
	}
	if jwt.SigningMethodHS256.Verify(parts[0]+"."+parts[1], sig, []byte(a.AppSecret)) != nil {
		return failed(TokenVerifyFailed)
	}
	// Reject fractional/exponent timestamps and missing fields before library parsing.
	for _, name := range []string{"iat", "nbf", "exp"} {
		value, err := strconv.ParseInt(string(payload[name]), 10, 64)
		if err != nil || value <= 0 || value > 253402300799 {
			return failed(TokenInvalid)
		}
	}
	claims := &authClaims{}
	payloadBytes, _ := decodeCanonical(parts[1])
	if json.Unmarshal(payloadBytes, claims) != nil {
		return failed(TokenInvalid)
	}
	if claims.Issuer != "quleban-auth" || claims.AppID != a.AppID || claims.TokenType != kind || !validUID(claims.UID) ||
		len(claims.Audience) != 1 || claims.Audience[0] != audience(kind) || claims.IssuedAt == nil || claims.NotBefore == nil || claims.ExpiresAt == nil ||
		!claims.ExpiresAt.After(claims.IssuedAt.Time) || !claims.ExpiresAt.After(claims.NotBefore.Time) || claims.NotBefore.Before(claims.IssuedAt.Time) {
		return failed(TokenInvalid)
	}
	id, e := decodeCanonical(claims.ID)
	if e != nil || len(id) != 16 {
		return failed(TokenInvalid)
	}
	token, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(a.AppSecret), nil
	}, jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("quleban-auth"),
		jwt.WithAudience(audience(kind)), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithStrictDecoding(), jwt.WithTimeFunc(func() time.Time { return now }))
	if err != nil {
		// Invalid signatures take precedence, even for expired tokens.
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return failed(TokenVerifyFailed)
		}
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return failed(TokenDecodeFailed)
		}
		if errors.Is(err, jwt.ErrTokenExpired) {
			return failed(TokenExpired)
		}
		return failed(TokenInvalid)
	}
	if token == nil || !token.Valid {
		return failed(TokenInvalid)
	}
	return &QuLeBanUid{Uid: claims.UID, IsSuccess: true, SdkErrorCode: TokenSuccess}
}

func decodeCanonical(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, errors.New("noncanonical base64url")
	}
	return decoded, nil
}

// Reject duplicate JSON object fields (including nested objects), to ensure all
// language implementations interpret the same signed claims.
func uniqueJSON(data []byte) bool {
	if !json.Valid(data) || !validSurrogates(data) {
		return false
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	if !scanJSON(d, 0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}

// encoding/json replaces isolated UTF-16 surrogate escapes with U+FFFD. Reject
// these instead, so the UID cannot change while moving between implementations.
func validSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xDC00 && value <= 0xDFFF {
			return false
		}
		if value < 0xD800 || value > 0xDBFF {
			continue
		}
		if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
			return false
		}
		low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
		if err != nil || low < 0xDC00 || low > 0xDFFF {
			return false
		}
		i += 6
	}
	return true
}

func scanJSON(d *json.Decoder, depth int) bool {
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	if depth >= 16 {
		return false
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return false
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return false
			}
			seen[key] = true
			if !scanJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !scanJSON(d, depth+1) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim(']')
	default:
		return false
	}
}
