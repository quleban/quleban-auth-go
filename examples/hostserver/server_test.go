package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	qulebanauth "github.com/quleban/quleban-auth-go"
)

const testSession = "public-test-session-only-0123456789"

func testSDK() *qulebanauth.QuLeBanAuth {
	return qulebanauth.NewQuLeBanAuth("qlb_000102030405060708090a0b0c0d0e0f", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
}
func demoHandler() http.Handler {
	return newHostHandler(testSDK(), &demoProvider{uid: "111", sessionToken: testSession}, newMemoryNonces(100))
}

type testResponse struct {
	RetCode      int             `json:"ret_code"`
	SDKErrorCode int             `json:"sdk_error_code"`
	Data         json.RawMessage `json:"data"`
}

func responseFrom(t *testing.T, w *httptest.ResponseRecorder) testResponse {
	t.Helper()
	var r testResponse
	if e := json.Unmarshal(w.Body.Bytes(), &r); e != nil {
		t.Fatal(e)
	}
	return r
}
func signedRequest(t *testing.T, path, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "https://host.invalid"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if e := testSDK().SignRequest(r); e != nil {
		t.Fatal(e)
	}
	return r
}
func callSigned(t *testing.T, h http.Handler, path, body string) testResponse {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signedRequest(t, path, body))
	if w.Code != 200 {
		t.Fatalf("unexpected status %d: %s", w.Code, w.Body.String())
	}
	return responseFrom(t, w)
}

func TestFullHostFlow(t *testing.T) {
	h := demoHandler()
	// Caller-supplied UID never overrides the server's authenticated session.
	r := httptest.NewRequest(http.MethodPost, "https://host.invalid/quleban/get_code?uid=attacker", strings.NewReader(`{"uid":"attacker"}`))
	r.Header.Set("Authorization", "Bearer "+testSession)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	result := responseFrom(t, w)
	if w.Code != 200 || result.RetCode != 0 {
		t.Fatalf("code: %s", w.Body.String())
	}
	var code struct {
		Code string `json:"code"`
	}
	json.Unmarshal(result.Data, &code)
	if got := testSDK().GetUidByCode(code.Code); !got.IsSuccess || got.Uid != "111" {
		t.Fatalf("untrusted UID used: %+v", got)
	}
	result = callSigned(t, h, "/quleban/get_sstoken", `{"code":"`+code.Code+`"}`)
	var token struct {
		SSToken       string `json:"ss_token"`
		ExpireDate    int64  `json:"expire_date"`
		ExpireDateStr string `json:"expire_date_str"`
	}
	json.Unmarshal(result.Data, &token)
	if result.RetCode != 0 || !testSDK().VerifySSToken(token.SSToken) || token.ExpireDate == 0 || token.ExpireDateStr == "" {
		t.Fatal("exchange failed")
	}
	result = callSigned(t, h, "/quleban/get_user_info", `{"ss_token":"`+token.SSToken+`"}`)
	var user UserInfo
	json.Unmarshal(result.Data, &user)
	if result.RetCode != 0 || user.UID != "111" || user.NickName != "开发测试用户" {
		t.Fatal("profile failed")
	}
	result = callSigned(t, h, "/quleban/update_sstoken", `{"ss_token":"`+token.SSToken+`"}`)
	var refreshed struct {
		SSToken string `json:"ss_token"`
	}
	json.Unmarshal(result.Data, &refreshed)
	if result.RetCode != 0 || refreshed.SSToken == token.SSToken || !testSDK().VerifySSToken(refreshed.SSToken) {
		t.Fatal("refresh failed")
	}
}

func TestHostRejectsUnauthenticatedAndReplayedRequests(t *testing.T) {
	h := demoHandler()
	for _, path := range []string{"/quleban/get_code", "/quleban/get_sstoken", "/quleban/get_user_info", "/quleban/update_sstoken"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader("{}")))
		if w.Code != 401 {
			t.Fatalf("%s accepted unauthenticated request", path)
		}
	}
	body := `{"code":"` + testSDK().GetCodeByDefaultDuration("111").Code + `"}`
	r := signedRequest(t, "/quleban/get_sstoken", body)
	r2 := r.Clone(context.Background())
	r2.Body = io.NopCloser(strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("first request rejected")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != 401 {
		t.Fatal("replay accepted")
	}
	wrong := testSDK().GetSSTokenByDefaultDuration("111").Token
	got := callSigned(t, h, "/quleban/get_sstoken", `{"code":"`+wrong+`"}`)
	if got.RetCode == 0 || got.SDKErrorCode != 1004 {
		t.Fatal("token kind confusion")
	}
}

func TestNonceStoreAtomicCapacityAndExpiration(t *testing.T) {
	n := newMemoryNonces(1)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, e := n.Consume(context.Background(), "app", "nonce", time.Now().Add(time.Minute))
			if e != nil {
				t.Error(e)
			}
			if ok {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("non-atomic replay consumption")
	}
	if _, e := n.Consume(context.Background(), "app", "second", time.Now().Add(time.Minute)); e == nil {
		t.Fatal("full cache must fail closed")
	}
	n.mu.Lock()
	n.entries["app:nonce"] = time.Now().Add(-time.Second)
	n.mu.Unlock()
	if ok, e := n.Consume(context.Background(), "app", "second", time.Now().Add(time.Minute)); e != nil || !ok {
		t.Fatal("expired entries not pruned")
	}
}
