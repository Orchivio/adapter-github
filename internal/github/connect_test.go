package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testClientID     = "Iv1.cid"
	testClientSecret = "csecret-value"
	testCode         = "code-value"
	testUserToken    = "ghu_usertoken"
	testRedirect     = "https://orchivio.example/oauth/callback/github"
	soemiiID         = 179956010
)

// account describes who owns the installation and who confirms it.
type account struct {
	Type, Login  string // installation account
	UserLogin    string // GET /user
	MemberStatus int    // GET /user/memberships/orgs/{org}; 0 means 200
	MemberRole   string
	MemberState  string
}

// soemiiUser is a user installation confirmed by its owner (login differs in case only).
var soemiiUser = account{Type: "User", Login: "Soemii", UserLogin: "soemii"}

// connectStub fakes the OAuth endpoint and the API calls of the connect flow.
// The user sees the installations in userIDs, served on page 2 after a full page 1.
func connectStub(t *testing.T, userIDs []int64, slugCalls *atomic.Int32, acct account) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Accept") != "application/json" || r.PostForm.Get("client_id") != testClientID ||
			r.PostForm.Get("client_secret") != testClientSecret || r.PostForm.Get("redirect_uri") != testRedirect {
			t.Errorf("bad token exchange %v %v", r.Header, r.PostForm)
		}
		if r.PostForm.Get("code") != testCode {
			io.WriteString(w, `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`)
			return
		}
		io.WriteString(w, `{"access_token":"`+testUserToken+`","token_type":"bearer","scope":""}`)
	})
	mux.HandleFunc("GET /user/installations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testUserToken || r.URL.Query().Get("per_page") != "100" {
			t.Errorf("bad user installations request %v %q", r.Header, r.URL.RawQuery)
		}
		var ids []int64
		switch r.URL.Query().Get("page") {
		case "1":
			for i := range 100 {
				ids = append(ids, int64(1000+i))
			}
		case "2":
			ids = userIDs
		}
		var items []map[string]any
		for _, id := range ids {
			items = append(items, map[string]any{"id": id})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": 100 + len(userIDs), "installations": items})
	})
	mux.HandleFunc("GET /app/installations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer "+testUserToken {
			t.Error("installation lookup must use the app JWT")
		}
		fmt.Fprintf(w, `{"id":%s,"account":{"login":%q,"type":%q}}`, r.PathValue("id"), acct.Login, acct.Type)
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testUserToken {
			t.Errorf("GET /user must use the user token")
		}
		fmt.Fprintf(w, `{"login":%q}`, acct.UserLogin)
	})
	mux.HandleFunc("GET /user/memberships/orgs/{org}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testUserToken || r.PathValue("org") != acct.Login {
			t.Errorf("bad membership request %v %q", r.Header, r.PathValue("org"))
		}
		if acct.MemberStatus != 0 {
			w.WriteHeader(acct.MemberStatus)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		fmt.Fprintf(w, `{"state":%q,"role":%q,"organization":{"login":%q}}`, acct.MemberState, acct.MemberRole, acct.Login)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) {
		slugCalls.Add(1)
		io.WriteString(w, `{"id":123,"slug":"orchivio"}`)
	})
	return mux
}

func newConnectApp(t *testing.T, h http.Handler, webURL string) *App {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	if webURL == "" {
		webURL = srv.URL
	}
	return NewApp(Config{APIURL: srv.URL, WebURL: webURL, AppID: 123, Key: testKey(t),
		ClientID: testClientID, ClientSecret: testClientSecret,
		Now: func() time.Time { return fixedNow }, HTTP: srv.Client()})
}

func TestBeginConnectUsesAppSlugAndState(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, nil, &slugCalls, soemiiUser), "https://github.com")
	for range 2 {
		got, err := app.BeginConnect(context.Background(), "s1")
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://github.com/apps/orchivio/installations/new?state=s1" {
			t.Fatalf("url = %q", got)
		}
	}
	if slugCalls.Load() != 1 {
		t.Fatalf("slug lookups = %d, want 1 (cached)", slugCalls.Load())
	}
}

func TestBeginConnectRequiresState(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, nil, &slugCalls, soemiiUser), "https://github.com")
	if _, err := app.BeginConnect(context.Background(), ""); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v", err)
	}
}

func completeQuery() map[string]string {
	return map[string]string{"code": testCode, "installation_id": strconv.Itoa(soemiiID), "setup_action": "install", "state": "s1"}
}

func TestCompleteConnectReturnsInstallationCredential(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, []int64{soemiiID}, &slugCalls, soemiiUser), "")
	inst, err := app.CompleteConnect(context.Background(), testRedirect, completeQuery())
	if err != nil {
		t.Fatal(err)
	}
	if inst != (Installation{ID: soemiiID, Account: "Soemii"}) {
		t.Fatalf("inst = %+v", inst)
	}
	data, _ := json.Marshal(inst)
	if string(data) != `{"installationId":179956010,"account":"Soemii"}` {
		t.Fatalf("data = %s", data)
	}
}

func TestCompleteConnectRejectsInstallationUserCannotAccess(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, []int64{42}, &slugCalls, soemiiUser), "")
	inst, err := app.CompleteConnect(context.Background(), testRedirect, completeQuery())
	if !errors.Is(err, ErrAccessDenied) || inst != (Installation{}) {
		t.Fatalf("inst=%+v err=%v", inst, err)
	}
	assertNoSecrets(t, err)
}

func TestCompleteConnectRequiresInstallationAdmin(t *testing.T) {
	org := account{Type: "Organization", Login: "Orchivio", UserLogin: "someone", MemberState: "active"}
	cases := []struct {
		name string
		acct account
		want error // nil means success
	}{
		{"org admin", withRole(org, "admin", "active", 0), nil},
		{"org member", withRole(org, "member", "active", 0), ErrAccessDenied},
		{"pending org admin", withRole(org, "admin", "pending", 0), ErrAccessDenied},
		{"no membership", withRole(org, "", "", http.StatusNotFound), ErrAccessDenied},
		{"membership forbidden", withRole(org, "", "", http.StatusForbidden), ErrAccessDenied},
		{"user installation by owner", soemiiUser, nil},
		{"user installation by another user", account{Type: "User", Login: "Soemii", UserLogin: "mallory"}, ErrAccessDenied},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var slugCalls atomic.Int32
			app := newConnectApp(t, connectStub(t, []int64{soemiiID}, &slugCalls, c.acct), "")
			inst, err := app.CompleteConnect(context.Background(), testRedirect, completeQuery())
			if c.want == nil {
				if err != nil || inst != (Installation{ID: soemiiID, Account: c.acct.Login}) {
					t.Fatalf("inst=%+v err=%v", inst, err)
				}
				return
			}
			if !errors.Is(err, c.want) || inst != (Installation{}) {
				t.Fatalf("inst=%+v err=%v", inst, err)
			}
			assertNoSecrets(t, err)
		})
	}
}

func withRole(a account, role, state string, status int) account {
	a.MemberRole, a.MemberState, a.MemberStatus = role, state, status
	return a
}

func TestCompleteConnectWithoutInstallationIDIsPendingApproval(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, nil, &slugCalls, soemiiUser), "")
	_, err := app.CompleteConnect(context.Background(), testRedirect, map[string]string{"code": testCode, "setup_action": "request"})
	if !errors.Is(err, ErrPendingApproval) || err.Error() != "installation pending approval by an organization owner" {
		t.Fatalf("err = %v", err)
	}
}

func TestCompleteConnectRejectsBadInput(t *testing.T) {
	var slugCalls atomic.Int32
	app := newConnectApp(t, connectStub(t, []int64{soemiiID}, &slugCalls, soemiiUser), "")
	cases := []map[string]string{
		{"installation_id": "1"},                       // no code
		{"code": testCode, "installation_id": "abc"},   // not a number
		{"code": "wrong-code", "installation_id": "1"}, // GitHub rejects the code
	}
	for _, q := range cases {
		_, err := app.CompleteConnect(context.Background(), testRedirect, q)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%v: err = %v", q, err)
		}
		assertNoSecrets(t, err)
	}
}

func assertNoSecrets(t *testing.T, err error) {
	t.Helper()
	for _, s := range []string{testUserToken, testClientSecret, testCode, "wrong-code", "ghs_"} {
		if err != nil && strings.Contains(err.Error(), s) {
			t.Errorf("error leaks %q: %v", s, err)
		}
	}
}

// accessStub mints installation tokens per id and lists repos per token.
func accessStub(t *testing.T, repos map[int64][]string, mints *atomic.Int32) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/{id}/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		mints.Add(1)
		w.WriteHeader(201)
		fmt.Fprintf(w, `{"token":"ghs_inst%s","expires_at":"2026-01-02T04:04:05Z"}`, r.PathValue("id"))
	})
	mux.HandleFunc("GET /installation/repositories", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ghs_inst"), 10, 64)
		var items []map[string]string
		if r.URL.Query().Get("page") == "1" {
			for _, n := range repos[id] {
				items = append(items, map[string]string{"full_name": n})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"total_count": len(repos[id]), "repositories": items})
	})
	return mux
}

func TestCheckAccessDeniesReposOutsideInstallations(t *testing.T) {
	var mints atomic.Int32
	app := newConnectApp(t, accessStub(t, map[int64][]string{1: {"Soemii/a"}}, &mints), "")
	installs := []Installation{{ID: 1, Account: "Soemii"}}
	denied, err := app.CheckAccess(context.Background(), installs, []string{"Soemii/a", "Other/b", "soemii/A", "Soemii/c", "bad repo"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(denied, []string{"Other/b", "Soemii/c", "bad repo"}) {
		t.Fatalf("denied = %v", denied)
	}
	if mints.Load() != 1 {
		t.Fatalf("token mints = %d, want 1 (cached per call)", mints.Load())
	}
}

func TestParseInstallation(t *testing.T) {
	got, err := ParseInstallation([]byte(`{"installationId":7,"account":"Soemii"}`))
	if err != nil || got != (Installation{ID: 7, Account: "Soemii"}) {
		t.Fatalf("%+v %v", got, err)
	}
	for _, bad := range []string{``, `{}`, `{"installationId":7}`, `{"account":"x"}`, `nope`} {
		if _, err := ParseInstallation([]byte(bad)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestCheckAccessSkipsRemovedInstallationsOfSameOwner(t *testing.T) {
	var mints atomic.Int32
	stub := accessStub(t, map[int64][]string{2: {"acme/a"}}, &mints)
	app := newConnectApp(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/1/access_tokens" {
			w.WriteHeader(404)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		stub.ServeHTTP(w, r)
	}), "")
	both := []Installation{{ID: 1, Account: "acme"}, {ID: 2, Account: "ACME"}}
	denied, err := app.CheckAccess(context.Background(), both, []string{"acme/a", "acme/b"})
	if err != nil || !slices.Equal(denied, []string{"acme/b"}) {
		t.Fatalf("denied = %v err = %v", denied, err)
	}
	denied, err = app.CheckAccess(context.Background(), both[:1], []string{"acme/a"})
	if err != nil || !slices.Equal(denied, []string{"acme/a"}) {
		t.Fatalf("only stale: denied = %v err = %v", denied, err)
	}
}
