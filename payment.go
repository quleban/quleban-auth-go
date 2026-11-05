package qulebanauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var ErrPaymentOrderInvalid = errors.New("qulebanauth: invalid payment order")
var ErrPaymentOrderExpired = errors.New("qulebanauth: payment order expired")

// PaymentOrder contains the platform-authenticated order. Use these fields for
// debiting; never use unsigned amounts or operations supplied by the APP client.
type PaymentOrder struct {
	AppID      string          `json:"app_id"`
	OrderID    string          `json:"order_id"`
	UID        string          `json:"uid"`
	GameID     string          `json:"mg_id"`
	RoomID     string          `json:"room_id"`
	RoundID    string          `json:"round_id"`
	Amount     int64           `json:"amount"`
	Action     string          `json:"action"`
	ActionName string          `json:"action_name"`
	ActionData json.RawMessage `json:"action_data"`
	ExpireAt   int64           `json:"expire_at"`
	CreatedAt  int64           `json:"created_at"`
}

// VerifyPaymentOrder verifies the registered order locally, before the APP
// debits its user. It does not contact the hall or mark an order as consumed.
// The caller must compare UID with its authenticated APP session and atomically
// bind OrderID to a single payment transaction in its own database.
func (a *QuLeBanAuth) VerifyPaymentOrder(token string) (*PaymentOrder, error) {
	return a.verifyPaymentOrderAt(token, time.Now().UnixMilli())
}

func (a *QuLeBanAuth) verifyPaymentOrderAt(token string, now int64) (*PaymentOrder, error) {
	if !a.validCredentials() || len(token) > 32768 {
		return nil, ErrPaymentOrderInvalid
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "qlbpay1" {
		return nil, ErrPaymentOrderInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(raw) > 16384 || base64.RawURLEncoding.EncodeToString(raw) != parts[1] {
		return nil, ErrPaymentOrderInvalid
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(sig) != sha256.Size || base64.RawURLEncoding.EncodeToString(sig) != parts[2] {
		return nil, ErrPaymentOrderInvalid
	}
	mac := hmac.New(sha256.New, []byte(a.AppSecret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) || !utf8.Valid(raw) || !uniqueJSON(raw) {
		return nil, ErrPaymentOrderInvalid
	}
	var order PaymentOrder
	if json.Unmarshal(raw, &order) != nil || order.AppID != a.AppID || !paymentUID(order.UID) ||
		!paymentID(order.OrderID, 128) || !paymentID(order.Action, 64) ||
		order.Amount <= 0 || order.Amount > 2147483647 ||
		strings.TrimSpace(order.ActionName) == "" || len(order.ActionName) > 512 ||
		len(order.ActionData) == 0 || len(order.ActionData) > 8192 || order.ActionData[0] != '{' ||
		order.CreatedAt <= 0 || order.CreatedAt > now+300000 || order.ExpireAt <= order.CreatedAt {
		return nil, ErrPaymentOrderInvalid
	}
	id, err := strconv.ParseInt(order.GameID, 10, 32)
	if err != nil || id <= 0 || strconv.FormatInt(id, 10) != order.GameID {
		return nil, ErrPaymentOrderInvalid
	}
	if order.ExpireAt <= now {
		return nil, ErrPaymentOrderExpired
	}
	return &order, nil
}

func paymentID(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == ':' || c == '.') {
			return false
		}
	}
	return true
}

// Payment UID follows the callback/bridge identity limit (256 UTF-16 code
// units), independently of the shorter code/SSToken-generation UID limit.
func paymentUID(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	units := 0
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
		units++
		if c > 0xffff {
			units++
		}
		if units > 256 {
			return false
		}
	}
	return true
}

// SignAPIRequest adds Authorization: QuLeBan-Auth for APP -> hall requests.
// SignRequest/VerifyRequest retain their four-header hall -> APP callback format.
func (a *QuLeBanAuth) SignAPIRequest(req *http.Request) error {
	if err := a.SignRequest(req); err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf(`QuLeBan-Auth app_id="%s",timestamp="%s",nonce="%s",signature="%s"`,
		req.Header.Get("Sud-AppId"), req.Header.Get("Sud-Timestamp"), req.Header.Get("Sud-Nonce"), req.Header.Get("Sud-Signature")))
	for _, name := range []string{"Sud-AppId", "Sud-Timestamp", "Sud-Nonce", "Sud-Signature"} {
		req.Header.Del(name)
	}
	return nil
}
