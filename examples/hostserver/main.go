// A loopback-only demo. Replace demoProvider with the host's real login session
// and user database adapter before exposing this to third-party users.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	qulebanauth "github.com/quleban/quleban-auth-go"
)

type demoProvider struct{ uid, sessionToken string }

func (p *demoProvider) AuthenticateApp(r *http.Request) (string, error) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", errors.New("unauthenticated")
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if subtle.ConstantTimeCompare([]byte(token), []byte(p.sessionToken)) != 1 {
		return "", errors.New("unauthenticated")
	}
	// The test identity belongs to this server-side session; body/query uid are not trusted.
	return p.uid, nil
}

func (p *demoProvider) UserInfo(_ context.Context, uid string) (UserInfo, error) {
	if uid != p.uid {
		return UserInfo{}, errors.New("unknown user")
	}
	return UserInfo{UID: uid, NickName: "开发测试用户", AvatarURL: "", Gender: ""}, nil
}

func main() {
	auth := &qulebanauth.QuLeBanAuth{
		AppID:     "平台提供的 AppID",
		AppSecret: "平台提供的 AppSecret",
	}
	provider := &demoProvider{
		uid:          "111",
		sessionToken: "REPLACE_WITH_RANDOM_SESSION_TOKEN",
	}
	// Optional local HTTPS certificate paths. Leave both empty for loopback HTTP.
	const cert = ""
	const key = ""
	if provider.uid == "" || len(provider.sessionToken) < 32 || strings.HasPrefix(provider.sessionToken, "REPLACE_") {
		log.Fatal("replace the demo sessionToken with your own random value of at least 32 characters")
	}
	if !auth.GetCodeByDefaultDuration(provider.uid).IsSuccess {
		log.Fatal("replace AppID and AppSecret with the credentials supplied by the platform; check the demo UID")
	}
	srv := &http.Server{Addr: "127.0.0.1:18080", Handler: newHostHandler(auth, provider, newMemoryNonces(10000)),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	if (cert == "") != (key == "") {
		log.Fatal("set both HTTPS certificate paths: cert and key")
	}
	log.Print("QuLeBan host demo listening on 127.0.0.1:18080; production must replace the demo identity adapter")
	var err error
	if cert != "" {
		err = srv.ListenAndServeTLS(cert, key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
