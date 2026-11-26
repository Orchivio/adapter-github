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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

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

func (f *fakeHost) StreamReviews(_ context.Context, installs []github.Installation, repos []string, every <-chan time.Time, send func(github.ReviewEvent) error) error {
	f.called, f.installs, f.repos = true, installs, repos
	if f.err != nil {
		return f.err
	}
	return send(github.ReviewEvent{ID: "ic:1", Repo: "acme/a", Branch: "orchivio/x", PRURL: "https://github.com/acme/a/pull/5",
		ActorID: 11, Login: "alice", Body: "hi @orchivio", MentionsBot: true})
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
		{fmt.Errorf("x: %w", github.ErrNotFound), codes.NotFound},
		{errors.New("GitHub API 401: Bad credentials"), codes.Unavailable}, // app-wide JWT, not tenant reauth
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
	if c.ContractVersion != "plugin.v1" || c.AdapterName != "github" || !c.SupportsReviewEvents || c.SupportsThreads || c.SupportsWebhooks {
		t.Fatalf("%+v", c)
	}
}

func TestIssueRepoCredentialsFillsTokens(t *testing.T) {
	s := New(&fakeHost{}, "https://github.com")
	got, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"acme/a", "acme/b"}, Credentials: acmeCreds})
	if err != nil {
		t.Fatal(err)
	}
	if got.CredentialId != "" || len(got.Tokens) != 2 {
		t.Fatalf("%+v", got)
	}
	for _, r := range []string{"acme/a", "acme/b"} {
		tok := got.Tokens[r]
		if tok.GetUsername() != "x-access-token" || tok.GetToken() != "tok" || tok.GetExpiresAt().AsTime().Unix() != 1000 {
			t.Errorf("%s: %+v", r, tok)
		}
	}
}

func TestRevokeRepoCredentialsIsNoop(t *testing.T) {
	f := &fakeHost{}
	_, err := New(f, "").RevokeRepoCredentials(context.Background(), &pluginv1.RevokeRepoCredentialsRequest{Credentials: acmeCreds})
	if err != nil || f.called {
		t.Fatalf("err=%v called=%v", err, f.called)
	}
}

// eventStream is a CodeHostAdapter_StreamEventsServer that records sent events.
type eventStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*pluginv1.CodeHostEvent
}

func (e *eventStream) Context() context.Context { return e.ctx }
func (e *eventStream) Send(ev *pluginv1.CodeHostEvent) error {
	e.sent = append(e.sent, ev)
	return nil
}

func TestStreamEventsMapsReviewEvents(t *testing.T) {
	f := &fakeHost{}
	st := &eventStream{ctx: context.Background()}
	if err := New(f, "").StreamEvents(&pluginv1.StreamCodeHostEventsRequest{Repos: []string{"acme/a"}, Credentials: acmeCreds}, st); err != nil {
		t.Fatal(err)
	}
	want := &pluginv1.CodeHostEvent{ExternalId: "ic:1", Kind: pluginv1.CodeHostEvent_REVIEW_COMMENTED, Repo: "acme/a", Branch: "orchivio/x",
		PrUrl: "https://github.com/acme/a/pull/5", Actor: &pluginv1.Actor{Id: "11", Username: "alice"}, Body: "hi @orchivio", MentionsBot: true}
	if len(st.sent) != 1 || !proto.Equal(st.sent[0], want) {
		t.Fatalf("sent %v", st.sent)
	}
	if !slices.Equal(f.repos, []string{"acme/a"}) || len(f.installs) != 1 {
		t.Fatalf("host got %+v %v", f.installs, f.repos)
	}
}

func TestStreamEventsValidatesAndMapsErrors(t *testing.T) {
	st := &eventStream{ctx: context.Background()}
	err := New(&fakeHost{}, "").StreamEvents(&pluginv1.StreamCodeHostEventsRequest{Repos: []string{"acme/a"}}, st)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no credentials: %v", err)
	}
	err = New(&fakeHost{err: fmt.Errorf("x: %w", github.ErrInvalidInput)}, "").StreamEvents(&pluginv1.StreamCodeHostEventsRequest{Repos: []string{"bad"}, Credentials: acmeCreds}, st)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad repo: %v", err)
	}
}
