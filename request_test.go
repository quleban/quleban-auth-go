package qulebanauth

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "https://host.invalid/quleban/%E8%B5%84%E6%96%99", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCallbackRoundtripAndBodyRestoration(t *testing.T) {
	a := testAuth()
	body := `{"ss_token":"demo","昵称":"玩家"}`
	req := makeRequest(t, body)
	if err := a.SignRequest(req); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyRequest(req); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyRequest(req); err != nil {
		t.Fatal("caller owns replay prevention; pure verification must remain repeatable", err)
	}
	data, err := io.ReadAll(req.Body)
	if err != nil || string(data) != body {
		t.Fatal("body not restored")
	}
}

func TestCallbackTampering(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"body", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"code":"changed"}`)) }},
		{"verb", func(r *http.Request) { r.Method = "GET" }},
		{"app", func(r *http.Request) { r.Header.Set("Sud-AppId", "another") }},
		{"nonce", func(r *http.Request) { r.Header.Set("Sud-Nonce", "00000000000000000000000000000000") }},
		{"missing header", func(r *http.Request) { r.Header.Del("Sud-Signature") }},
		{"duplicate header", func(r *http.Request) { r.Header.Add("Sud-Signature", r.Header.Get("Sud-Signature")) }},
		{"stale", func(r *http.Request) { r.Header.Set("Sud-Timestamp", "1") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := makeRequest(t, `{"code":"original"}`)
			if e := testAuth().SignRequest(r); e != nil {
				t.Fatal(e)
			}
			tc.mutate(r)
			if testAuth().VerifyRequest(r) == nil {
				t.Fatal("tampered callback accepted")
			}
		})
	}
}

func TestCallbackLimitsAndFailures(t *testing.T) {
	for _, size := range []int{65536, 65537, 70000} {
		body := strings.Repeat("a", size)
		r := makeRequest(t, body)
		err := testAuth().SignRequest(r)
		if (err == nil) != (size <= 65536) {
			t.Fatalf("bad body size handling %d", size)
		}
		got, _ := io.ReadAll(r.Body)
		if !bytes.Equal(got, []byte(body)) {
			t.Fatal("oversize body was truncated")
		}
	}
	if testAuth().SignRequest(nil) == nil || testAuth().VerifyRequest(nil) == nil {
		t.Fatal("nil request accepted")
	}
	var nilAuth *QuLeBanAuth
	if nilAuth.SignRequest(makeRequest(t, "")) == nil {
		t.Fatal("nil credentials accepted")
	}
}

func TestCallbackClockBoundary(t *testing.T) {
	r := makeRequest(t, `{}`)
	a := testAuth()
	if err := a.SignRequest(r); err != nil {
		t.Fatal(err)
	}
	stamp, _ := strconv.ParseInt(r.Header.Get("Sud-Timestamp"), 10, 64)
	now := time.UnixMilli(stamp)
	if err := a.verifyRequestAt(r, now.Add(300*time.Second)); err != nil {
		t.Fatal("300 second window inclusive", err)
	}
	if err := a.verifyRequestAt(r, now.Add(301*time.Second)); err == nil {
		t.Fatal("stale callback accepted")
	}
}

func TestSudCallbackIndependentVector(t *testing.T) {
	// Computed independently with Node crypto.createHmac("sha1", secret).
	const expected = "be63f2913eebb3aec22e15964fca63ea5791a6f6"
	const stamp = "1700000010000"
	const nonce = "keVJLJTItd1VBtGT"
	const body = `{"code":"public-fixture"}`
	r := makeRequest(t, body)
	r.Header.Set("Sud-AppId", testAppID)
	r.Header.Set("Sud-Timestamp", stamp)
	r.Header.Set("Sud-Nonce", nonce)
	r.Header.Set("Sud-Signature", expected)
	if err := testAuth().verifyRequestAt(r, time.UnixMilli(1700000010000)); err != nil {
		t.Fatal("official callback wire format incompatible", err)
	}
	// The official signature covers the raw body, not routing path/query.
	r.URL.Path, r.URL.RawPath, r.URL.RawQuery = "/another-prefix/get_sstoken", "", "env=test"
	if err := testAuth().verifyRequestAt(r, time.UnixMilli(1700000010000)); err != nil {
		t.Fatal("proxy routing must not alter the signature", err)
	}
	r.Body = io.NopCloser(strings.NewReader(body + "\n"))
	if testAuth().verifyRequestAt(r, time.UnixMilli(1700000010000)) == nil {
		t.Fatal("raw body change accepted")
	}
}
