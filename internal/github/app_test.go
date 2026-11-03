package github

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newTestApp(t *testing.T, h http.Handler) (*App, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return NewApp(srv.URL, 123, testKey(t), func() time.Time { return fixedNow }, srv.Client()), srv
}

func TestJWTClaims(t *testing.T) {
	app := NewApp("http://x", 123, testKey(t), func() time.Time { return fixedNow }, nil)
	tok, err := app.jwt()
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	dec := func(s string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var hdr map[string]string
	_ = json.Unmarshal(dec(parts[0]), &hdr)
	if hdr["alg"] != "RS256" || hdr["typ"] != "JWT" {
		t.Fatalf("header = %v", hdr)
	}
	var c struct {
		Iss string
		Iat int64
		Exp int64
	}
	_ = json.Unmarshal([]byte(strings.ToLower(string(dec(parts[1])))), &c)
	if c.Iss != "123" || c.Exp-c.Iat != 600 || c.Iat != fixedNow.Add(-60*time.Second).Unix() {
		t.Fatalf("claims = %+v", c)
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&app.key.PublicKey, crypto.SHA256, sum[:], dec(parts[2])); err != nil {
		t.Fatalf("signature: %v", err)
	}
}

func TestParsePrivateKeyPKCS1AndPKCS8(t *testing.T) {
	k := testKey(t)
	p1 := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	der8, _ := x509.MarshalPKCS8PrivateKey(k)
	p8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der8})
	for _, p := range [][]byte{p1, p8} {
		got, err := ParsePrivateKey(string(p))
		if err != nil || !got.Equal(k) {
			t.Fatalf("err=%v", err)
		}
	}
	_, err := ParsePrivateKey("SECRETMATERIAL not pem")
	if err == nil || strings.Contains(err.Error(), "SECRETMATERIAL") {
		t.Fatalf("err = %v", err)
	}
}

type tokenReq struct {
	Repositories []string          `json:"repositories"`
	Permissions  map[string]string `json:"permissions"`
}

// githubStub serves installation lookup and token minting; records token requests.
func githubStub(t *testing.T, got *[]tokenReq, lookups *atomic.Int32) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /repos/{owner}/{repo}/installation", func(w http.ResponseWriter, r *http.Request) {
		lookups.Add(1)
		if r.Header.Get("Accept") != "application/vnd.github+json" || r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" ||
			!strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			t.Errorf("bad headers %v", r.Header)
		}
		if r.PathValue("owner") == "ghost" {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		io.WriteString(w, `{"id":77}`)
	})
	mux.HandleFunc("POST /app/installations/77/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		var tr tokenReq
		_ = json.NewDecoder(r.Body).Decode(&tr)
		*got = append(*got, tr)
		w.WriteHeader(201)
		io.WriteString(w, `{"token":"ghs_tok","expires_at":"2026-01-02T04:04:05Z"}`)
	})
	return mux
}

func TestInstallationTokenScopesReposAndPermission(t *testing.T) {
	cases := []struct {
		write bool
		want  map[string]string
	}{
		{false, map[string]string{"contents": "read", "metadata": "read"}},
		{true, map[string]string{"contents": "write", "metadata": "read"}},
	}
	for _, c := range cases {
		var got []tokenReq
		var n atomic.Int32
		app, _ := newTestApp(t, githubStub(t, &got, &n))
		tok, exp, err := app.InstallationToken(context.Background(), []string{"acme/playground", "ACME/other", "acme/playground"}, c.write)
		if err != nil {
			t.Fatal(err)
		}
		if tok != "ghs_tok" || !exp.Equal(time.Date(2026, 1, 2, 4, 4, 5, 0, time.UTC)) {
			t.Fatalf("tok=%q exp=%v", tok, exp)
		}
		r := got[0]
		if len(r.Repositories) != 2 || r.Repositories[0] != "playground" || r.Repositories[1] != "other" {
			t.Fatalf("repos = %v", r.Repositories)
		}
		if len(r.Permissions) != 2 || r.Permissions["contents"] != c.want["contents"] || r.Permissions["metadata"] != "read" {
			t.Fatalf("perms = %v", r.Permissions)
		}
	}
}

func TestInstallationIDCachedPerOwner(t *testing.T) {
	var got []tokenReq
	var n atomic.Int32
	app, _ := newTestApp(t, githubStub(t, &got, &n))
	for range 2 {
		if _, _, err := app.InstallationToken(context.Background(), []string{"acme/a"}, false); err != nil {
			t.Fatal(err)
		}
	}
	if n.Load() != 1 {
		t.Fatalf("lookups = %d", n.Load())
	}
}

func TestInstallationTokenRejectsInvalidRepos(t *testing.T) {
	var got []tokenReq
	var n atomic.Int32
	app, _ := newTestApp(t, githubStub(t, &got, &n))
	bad := [][]string{nil, {"a/b", "c/d"}, {"noslash"}, {"a/.."}, {"a/b/c"}, {"a/b c"}, {"../x"}}
	for _, repos := range bad {
		_, _, err := app.InstallationToken(context.Background(), repos, false)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%v: err = %v", repos, err)
		}
	}
	if n.Load() != 0 || len(got) != 0 {
		t.Fatal("GitHub must not be called for invalid input")
	}
}

func TestInstallationTokenNotInstalled(t *testing.T) {
	var got []tokenReq
	var n atomic.Int32
	app, _ := newTestApp(t, githubStub(t, &got, &n))
	_, _, err := app.InstallationToken(context.Background(), []string{"ghost/x"}, false)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIErrorShowsStatusAndMessageOnly(t *testing.T) {
	app, _ := newTestApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Secret", "hdrsecret")
		w.WriteHeader(500)
		io.WriteString(w, `{"message":"boom","other":"bodysecret"}`)
	}))
	_, _, err := app.InstallationToken(context.Background(), []string{"acme/a"}, false)
	if err == nil || !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "boom") ||
		strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenPullRequestPostsHeadAndBase(t *testing.T) {
	var prBody map[string]string
	var prAuth string
	var tokReq []tokenReq
	var n atomic.Int32
	stub := githubStub(t, &tokReq, &n).(*http.ServeMux)
	stub.HandleFunc("POST /repos/acme/playground/pulls", func(w http.ResponseWriter, r *http.Request) {
		prAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&prBody)
		w.WriteHeader(201)
		io.WriteString(w, `{"html_url":"https://github.com/acme/playground/pull/9","number":9}`)
	})
	app, _ := newTestApp(t, stub)
	url, num, err := app.OpenPullRequest(context.Background(), "acme/playground", "main", "orchivio/orc-1-abcd1234", "T", "B")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://github.com/acme/playground/pull/9" || num != 9 {
		t.Fatalf("%q %d", url, num)
	}
	if prBody["head"] != "orchivio/orc-1-abcd1234" || prBody["base"] != "main" || prBody["title"] != "T" || prBody["body"] != "B" {
		t.Fatalf("body = %v", prBody)
	}
	if prAuth != "Bearer ghs_tok" {
		t.Fatalf("auth = %q", prAuth)
	}
	p := tokReq[0]
	if len(p.Repositories) != 1 || p.Repositories[0] != "playground" || p.Permissions["pull_requests"] != "write" ||
		p.Permissions["metadata"] != "read" || len(p.Permissions) != 2 {
		t.Fatalf("token req = %+v", p)
	}
}
