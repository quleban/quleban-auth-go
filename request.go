package qulebanauth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxBodyBytes = 64 * 1024

// SignRequest signs an outgoing POST callback. It restores the body after reading
// it. This function does not send the request or perform any network operation.
func (a *QuLeBanAuth) SignRequest(req *http.Request) error {
	if !a.validCredentials() {
		return errors.New("qulebanauth: invalid application credentials")
	}
	if !validRequest(req) {
		return errors.New("qulebanauth: callback must be a POST request with a path")
	}
	body, err := readRequestBody(req)
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return errors.New("qulebanauth: nonce generation failed")
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	nonceText := hex.EncodeToString(nonce)
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	req.Header.Set("Sud-AppId", a.AppID)
	req.Header.Set("Sud-Timestamp", ts)
	req.Header.Set("Sud-Nonce", nonceText)
	req.Header.Set("Sud-Signature", requestSignature(a.AppSecret, req.URL.EscapedPath(), a.AppID, ts, nonceText, body))
	return nil
}

// VerifyRequest verifies callback identity, body integrity and a +/-300 second
// timestamp window. It restores the body, and never sends a network request.
// The caller MUST also consume AppID+nonce atomically in a replay store before
// executing the callback. This method alone does not prevent request replay.
func (a *QuLeBanAuth) VerifyRequest(req *http.Request) error {
	return a.verifyRequestAt(req, time.Now())
}

func (a *QuLeBanAuth) verifyRequestAt(req *http.Request, now time.Time) error {
	if !a.validCredentials() || !validRequest(req) {
		return errors.New("qulebanauth: invalid callback")
	}
	values := make([]string, 4)
	for i, key := range []string{"Sud-AppId", "Sud-Timestamp", "Sud-Nonce", "Sud-Signature"} {
		v := req.Header.Values(key)
		if len(v) != 1 || v[0] == "" {
			return errors.New("qulebanauth: missing or duplicate signature header")
		}
		values[i] = v[0]
	}
	appID, ts, nonce, signature := values[0], values[1], values[2], values[3]
	if appID != a.AppID {
		return errors.New("qulebanauth: application mismatch")
	}
	millis, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || strconv.FormatInt(millis, 10) != ts || millis < now.UnixMilli()-300000 || millis > now.UnixMilli()+300000 {
		return errors.New("qulebanauth: invalid callback timestamp")
	}
	if len(nonce) < 1 || len(nonce) > 128 || strings.ContainsAny(nonce, "\r\n") || !lowerHex(signature, 40) {
		return errors.New("qulebanauth: invalid signature encoding")
	}
	body, err := readRequestBody(req)
	if err != nil {
		return err
	}
	expected := requestSignature(a.AppSecret, req.URL.EscapedPath(), appID, ts, nonce, body)
	if !hmac.Equal([]byte(signature), []byte(expected)) {
		return errors.New("qulebanauth: callback signature mismatch")
	}
	return nil
}

func lowerHex(s string, length int) bool {
	if len(s) != length || s != strings.ToLower(s) {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validRequest(req *http.Request) bool {
	return req != nil && req.URL != nil && req.Method == http.MethodPost && strings.HasPrefix(req.URL.EscapedPath(), "/")
}

func readRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	original := req.Body
	body, err := io.ReadAll(io.LimitReader(original, maxBodyBytes+1))
	// Leave unread bytes available even when the limit is exceeded.
	req.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(body), original), original: original}
	if err != nil {
		return nil, errors.New("qulebanauth: could not read callback body")
	}
	if len(body) > maxBodyBytes {
		return nil, errors.New("qulebanauth: callback body exceeds 64 KiB")
	}
	return body, nil
}

type restoredBody struct {
	io.Reader
	original io.Closer
}

func (r *restoredBody) Close() error { return r.original.Close() }

func requestSignature(secret, _ string, appID, ts, nonce string, body []byte) string {
	canonical := appID + "\n" + ts + "\n" + nonce + "\n" + string(body) + "\n"
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(canonical))
	return hex.EncodeToString(mac.Sum(nil))
}
