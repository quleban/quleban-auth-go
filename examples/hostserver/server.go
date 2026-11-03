package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"sync"
	"time"

	qulebanauth "github.com/quleban/quleban-auth-go"
)

type UserInfo struct {
	UID       string `json:"uid"`
	NickName  string `json:"nick_name"`
	AvatarURL string `json:"avatar_url"`
	Gender    string `json:"gender"`
}

// Implement this adapter with the host's existing session and user database.
// AuthenticateApp must derive identity from a verified session, not a uid field.
type IdentityProvider interface {
	AuthenticateApp(*http.Request) (string, error)
	UserInfo(context.Context, string) (UserInfo, error)
}

// Consume must atomically accept each (appID, nonce) once until expiresAt.
// Multi-instance production servers need a shared implementation, e.g. Redis
// SET key value NX EX ttl; a per-process map is insufficient across instances.
type NonceStore interface {
	Consume(ctx context.Context, appID, nonce string, expiresAt time.Time) (bool, error)
}

type hostServer struct {
	auth     *qulebanauth.QuLeBanAuth
	provider IdentityProvider
	nonces   NonceStore
}

func newHostHandler(auth *qulebanauth.QuLeBanAuth, provider IdentityProvider, nonces NonceStore) http.Handler {
	s := &hostServer{auth: auth, provider: provider, nonces: nonces}
	mux := http.NewServeMux()
	mux.HandleFunc("/quleban/get_code", s.getCode)
	mux.HandleFunc("/quleban/get_sstoken", s.callback(s.exchange))
	mux.HandleFunc("/quleban/update_sstoken", s.callback(s.refresh))
	mux.HandleFunc("/quleban/get_user_info", s.callback(s.userInfo))
	return mux
}

type response struct {
	RetCode      int         `json:"ret_code"`
	RetMsg       string      `json:"ret_msg"`
	SDKErrorCode int         `json:"sdk_error_code"`
	Data         interface{} `json:"data"`
}

func reply(w http.ResponseWriter, status, ret, sdk int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if data == nil {
		data = struct{}{}
	}
	_ = json.NewEncoder(w).Encode(response{RetCode: ret, RetMsg: message, SDKErrorCode: sdk, Data: data})
}

func (s *hostServer) getCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		reply(w, 405, 1, 0, "POST required", nil)
		return
	}
	uid, err := s.provider.AuthenticateApp(r)
	if err != nil {
		reply(w, 401, 1, 0, "host login required", nil)
		return
	}
	// Check the user still exists/is allowed before issuing a new credential.
	profile, err := s.provider.UserInfo(r.Context(), uid)
	if err != nil || profile.UID != uid {
		reply(w, 403, 1, 0, "user unavailable", nil)
		return
	}
	code := s.auth.GetCodeByDefaultDuration(uid)
	if !code.IsSuccess {
		reply(w, 200, 1, code.SdkErrorCode, "code creation failed", nil)
		return
	}
	reply(w, 200, 0, 0, "", map[string]interface{}{"code": code.Code, "expire_date": code.ExpireDate, "expire_date_str": strconv.FormatInt(code.ExpireDate, 10)})
}

func (s *hostServer) callback(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.nonces == nil || s.auth.VerifyRequest(r) != nil {
			reply(w, 401, 1, 0, "callback authentication failed", nil)
			return
		}
		stamp, _ := strconv.ParseInt(r.Header.Get("Sud-Timestamp"), 10, 64)
		// Retain through the entire timestamp acceptance window, including its final second.
		ok, err := s.nonces.Consume(r.Context(), s.auth.AppID, r.Header.Get("Sud-Nonce"), time.UnixMilli(stamp).Add(301*time.Second))
		if err != nil {
			reply(w, 503, 1, 0, "callback replay store unavailable", nil)
			return
		}
		if !ok {
			reply(w, 401, 1, 0, "callback already used", nil)
			return
		}
		next(w, r)
	}
}

func readJSON(r *http.Request, target interface{}) error {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		return errors.New("application/json required")
	}
	d := json.NewDecoder(io.LimitReader(r.Body, 65537))
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra interface{}
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func (s *hostServer) exchange(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if readJSON(r, &body) != nil || body.Code == "" {
		reply(w, 400, 1, 0, "invalid code request", nil)
		return
	}
	identity := s.auth.GetUidByCode(body.Code)
	if !identity.IsSuccess {
		reply(w, 200, 1, identity.SdkErrorCode, "invalid code", nil)
		return
	}
	s.issueToken(w, r, identity.Uid)
}

func (s *hostServer) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"ss_token"`
	}
	if readJSON(r, &body) != nil || body.Token == "" {
		reply(w, 400, 1, 0, "invalid token request", nil)
		return
	}
	identity := s.auth.GetUidBySSToken(body.Token)
	if !identity.IsSuccess {
		reply(w, 200, 1, identity.SdkErrorCode, "invalid SSToken", nil)
		return
	}
	s.issueToken(w, r, identity.Uid)
}

func (s *hostServer) issueToken(w http.ResponseWriter, r *http.Request, uid string) {
	profile, err := s.provider.UserInfo(r.Context(), uid)
	if err != nil || profile.UID != uid {
		reply(w, 200, 1, 0, "user unavailable", nil)
		return
	}
	token := s.auth.GetSSTokenByDefaultDuration(uid)
	if !token.IsSuccess {
		reply(w, 200, 1, token.SdkErrorCode, "token creation failed", nil)
		return
	}
	reply(w, 200, 0, 0, "", map[string]interface{}{"ss_token": token.Token, "expire_date": token.ExpireDate, "expire_date_str": strconv.FormatInt(token.ExpireDate, 10), "user_info": profile})
}

func (s *hostServer) userInfo(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"ss_token"`
	}
	if readJSON(r, &body) != nil || body.Token == "" {
		reply(w, 400, 1, 0, "invalid token request", nil)
		return
	}
	identity := s.auth.GetUidBySSToken(body.Token)
	if !identity.IsSuccess {
		reply(w, 200, 1, identity.SdkErrorCode, "invalid SSToken", nil)
		return
	}
	profile, err := s.provider.UserInfo(r.Context(), identity.Uid)
	if err != nil || profile.UID != identity.Uid {
		reply(w, 200, 1, 0, "user unavailable", nil)
		return
	}
	reply(w, 200, 0, 0, "", profile)
}

// memoryNonces is bounded and concurrency safe, suitable for the single-process
// demo only. Full capacity fails closed instead of evicting live nonces.
type memoryNonces struct {
	mu       sync.Mutex
	entries  map[string]time.Time
	capacity int
}

func newMemoryNonces(capacity int) *memoryNonces {
	return &memoryNonces{entries: make(map[string]time.Time), capacity: capacity}
}

func (m *memoryNonces) Consume(ctx context.Context, appID, nonce string, expiresAt time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for key, expiry := range m.entries {
		if !expiry.After(now) {
			delete(m.entries, key)
		}
	}
	key := appID + ":" + nonce
	if _, exists := m.entries[key]; exists {
		return false, nil
	}
	if len(m.entries) >= m.capacity {
		return false, errors.New("nonce cache full")
	}
	m.entries[key] = expiresAt
	return true, nil
}
