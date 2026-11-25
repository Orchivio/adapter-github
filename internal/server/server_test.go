package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/orchivio/orchestrator/contract/gen/orchivio/plugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/orchivio/adapter-github/internal/github"
)

type fakeHost struct {
	err      error
	installs []github.Installation
	repos    []string
	write    bool
	called   bool
	query    map[string]string
	redirect string
}

func (f *fakeHost) InstallationToken(_ context.Context, installs []github.Installation, repos []string, write bool) (string, time.Time, error) {
	f.called, f.installs, f.repos, f.write = true, installs, repos, write
	return "tok", time.Unix(1000, 0), f.err
}

func (f *fakeHost) OpenPullRequest(_ context.Context, installs []github.Installation, repo, base, head, title, body string) (string, int64, error) {
	f.called, f.installs = true, installs
	return "https://x/pull/1", 1, f.err
}

func (f *fakeHost) BeginConnect(_ context.Context, state string) (string, error) {
	f.called = true
	return "https://github.com/apps/orchivio/installations/new?state=" + state, f.err
}

func (f *fakeHost) CompleteConnect(_ context.Context, redirectURI string, query map[string]string) (github.Installation, error) {
	f.called, f.redirect, f.query = true, redirectURI, query
	return github.Installation{ID: 179956010, Account: "Soemii"}, f.err
}

func (f *fakeHost) CheckAccess(_ context.Context, installs []github.Installation, repos []string) ([]string, error) {
	f.called, f.installs, f.repos = true, installs, repos
	return []string{"Other/b"}, f.err
}

func cred(data string) *pluginv1.Credential { return &pluginv1.Credential{Data: []byte(data)} }

var acmeCreds = []*pluginv1.Credential{cred(`{"installationId":77,"account":"acme"}`)}

func TestIssueRepoCredentialsMapsCloneURLs(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "https://github.com")
	got, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"acme/a", "acme/b.c"}, Write: true, Credentials: acmeCreds})
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "x-access-token" || got.Token != "tok" || got.ExpiresAt.AsTime().Unix() != 1000 || !f.write {
		t.Fatalf("%+v", got)
	}
	if got.CloneUrls["acme/a"] != "https://github.com/acme/a.git" || got.CloneUrls["acme/b.c"] != "https://github.com/acme/b.c.git" {
		t.Fatalf("%v", got.CloneUrls)
	}
	if len(f.installs) != 1 || f.installs[0] != (github.Installation{ID: 77, Account: "acme"}) {
		t.Fatalf("installs = %+v", f.installs)
	}
}

func TestCallsWithoutCredentialsAreInvalidArgument(t *testing.T) {
	for name, creds := range map[string][]*pluginv1.Credential{"none": nil, "garbage": {cred(`{"token":"SECRETDATA"}`)}} {
		f := &fakeHost{}
		s := New(f, "https://github.com")
		_, err1 := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"acme/a"}, Credentials: creds})
		_, err2 := s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "acme/a", Base: "main", Head: "h", Title: "t", Credentials: creds})
		for _, err := range []error{err1, err2} {
			if status.Code(err) != codes.InvalidArgument || strings.Contains(err.Error(), "SECRETDATA") {
				t.Errorf("%s: %v", name, err)
			}
		}
		if f.called {
			t.Errorf("%s: host must not be called", name)
		}
	}
}

func TestErrorsMapToGRPCCodes(t *testing.T) {
	cases := []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("x: %w", github.ErrInvalidInput), codes.InvalidArgument},
		{&github.NotInstalledError{Owner: "ghost"}, codes.FailedPrecondition},
		{github.ErrPendingApproval, codes.FailedPrecondition},
		{github.ErrAccessDenied, codes.PermissionDenied},
		{errors.New("GitHub API 500: boom"), codes.Unavailable},
	}
	for _, c := range cases {
		s := New(&fakeHost{err: c.err}, "https://github.com")
		_, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"o/r"}, Credentials: acmeCreds})
		if status.Code(err) != c.want {
			t.Errorf("%v: code = %v", c.err, status.Code(err))
		}
		_, err = s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Base: "main", Head: "h", Title: "t", Credentials: acmeCreds})
		if status.Code(err) != c.want {
			t.Errorf("PR %v: code = %v", c.err, status.Code(err))
		}
		_, err = s.CompleteConnect(context.Background(), &pluginv1.CompleteConnectRequest{Query: map[string]string{"code": "c"}})
		if status.Code(err) != c.want {
			t.Errorf("complete %v: code = %v", c.err, status.Code(err))
		}
	}
}

func TestNotInstalledMessageNamesOwnerOnly(t *testing.T) {
	s := New(&fakeHost{err: &github.NotInstalledError{Owner: "ghost"}}, "https://github.com")
	_, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"ghost/r"}, Credentials: acmeCreds})
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != "no usable installation for owner ghost" {
		t.Fatalf("%v", err)
	}
}

func TestOpenPullRequestValidatesInput(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "https://github.com")
	_, err := s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Head: "h", Credentials: acmeCreds})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("%v", err)
	}
	got, err := s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Base: "main", Head: "h", Title: "t", Credentials: acmeCreds})
	if err != nil || got.Number != 1 || got.Url != "https://x/pull/1" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestBeginConnectReturnsInstallURL(t *testing.T) {
	s := New(&fakeHost{}, "")
	got, err := s.BeginConnect(context.Background(), &pluginv1.BeginConnectRequest{Tenant: "t1", RedirectUri: "https://o/cb", State: "s1"})
	if err != nil || got.Url != "https://github.com/apps/orchivio/installations/new?state=s1" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestCompleteConnectMapsInstallationToCredential(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "")
	q := map[string]string{"code": "c", "installation_id": "179956010"}
	got, err := s.CompleteConnect(context.Background(), &pluginv1.CompleteConnectRequest{RedirectUri: "https://o/cb", Query: q})
	if err != nil {
		t.Fatal(err)
	}
	if got.Label != "Soemii" || got.ExternalId != "179956010" || got.Credential.RefreshAfter != nil ||
		string(got.Credential.Data) != `{"installationId":179956010,"account":"Soemii"}` {
		t.Fatalf("%+v", got)
	}
	if f.redirect != "https://o/cb" || f.query["installation_id"] != "179956010" {
		t.Fatalf("host got %q %v", f.redirect, f.query)
	}
}

func TestRefreshReturnsCredentialUnchangedAndDisconnectIsNoop(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "")
	c := cred(`{"installationId":77,"account":"acme"}`)
	got, err := s.RefreshCredential(context.Background(), &pluginv1.RefreshCredentialRequest{Credential: c})
	if err != nil || string(got.Data) != string(c.Data) || got.RefreshAfter != nil {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := s.Disconnect(context.Background(), &pluginv1.DisconnectRequest{Credential: c}); err != nil || f.called {
		t.Fatalf("err=%v called=%v", err, f.called)
	}
}

func TestCheckAccessPassesInstallationsAndDenied(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "")
	got, err := s.CheckAccess(context.Background(), &pluginv1.CheckAccessRequest{Credentials: acmeCreds, Items: []string{"acme/a", "Other/b"}})
	if err != nil || !slices.Equal(got.Denied, []string{"Other/b"}) {
		t.Fatalf("%v %v", got, err)
	}
	if len(f.installs) != 1 || f.installs[0].ID != 77 || !slices.Equal(f.repos, []string{"acme/a", "Other/b"}) {
		t.Fatalf("host got %+v %v", f.installs, f.repos)
	}
}

func TestCheckAccessWithoutCredentialsDeniesAll(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "")
	got, err := s.CheckAccess(context.Background(), &pluginv1.CheckAccessRequest{Items: []string{"acme/a", "b/c"}})
	if err != nil || !slices.Equal(got.Denied, []string{"acme/a", "b/c"}) || f.called {
		t.Fatalf("%v %v called=%v", got, err, f.called)
	}
}

func TestGetCapabilities(t *testing.T) {
	c, _ := New(&fakeHost{}, "").GetCapabilities(context.Background(), &pluginv1.GetCapabilitiesRequest{})
	if c.ContractVersion != "plugin.v1" || c.AdapterName != "github" || c.SupportsThreads || c.SupportsWebhooks {
		t.Fatalf("%+v", c)
	}
}
