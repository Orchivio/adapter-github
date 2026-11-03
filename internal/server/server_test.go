package server

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	pluginv1 "github.com/soemii/orchivio-server/contract/gen/orchivio/plugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/soemii/orchivio-adapter-github/internal/github"
)

type fakeHost struct {
	err    error
	repos  []string
	write  bool
	called bool
}

func (f *fakeHost) InstallationToken(_ context.Context, repos []string, write bool) (string, time.Time, error) {
	f.called, f.repos, f.write = true, repos, write
	return "tok", time.Unix(1000, 0), f.err
}

func (f *fakeHost) OpenPullRequest(_ context.Context, repo, base, head, title, body string) (string, int64, error) {
	return "https://x/pull/1", 1, f.err
}

func TestIssueRepoCredentialsMapsCloneURLs(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "https://github.com")
	got, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"acme/a", "acme/b.c"}, Write: true})
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "x-access-token" || got.Token != "tok" || got.ExpiresAt.AsTime().Unix() != 1000 || !f.write {
		t.Fatalf("%+v", got)
	}
	if got.CloneUrls["acme/a"] != "https://github.com/acme/a.git" || got.CloneUrls["acme/b.c"] != "https://github.com/acme/b.c.git" {
		t.Fatalf("%v", got.CloneUrls)
	}
}

func TestErrorsMapToGRPCCodes(t *testing.T) {
	cases := []struct {
		err  error
		want codes.Code
	}{
		{fmt.Errorf("x: %w", github.ErrInvalidInput), codes.InvalidArgument},
		{fmt.Errorf("x: %w", github.ErrNotInstalled), codes.NotFound},
		{errors.New("GitHub API 500: boom"), codes.Unavailable},
	}
	for _, c := range cases {
		s := New(&fakeHost{err: c.err}, "https://github.com")
		_, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"o/r"}})
		if status.Code(err) != c.want {
			t.Errorf("%v: code = %v", c.err, status.Code(err))
		}
		_, err = s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Base: "main", Head: "h", Title: "t"})
		if status.Code(err) != c.want {
			t.Errorf("PR %v: code = %v", c.err, status.Code(err))
		}
	}
}

func TestNotInstalledMessageNamesOwnerOnly(t *testing.T) {
	s := New(&fakeHost{err: &github.NotInstalledError{Owner: "ghost"}}, "https://github.com")
	_, err := s.IssueRepoCredentials(context.Background(), &pluginv1.IssueRepoCredentialsRequest{Repos: []string{"ghost/r"}})
	if status.Code(err) != codes.NotFound || status.Convert(err).Message() != "GitHub App not installed for ghost" {
		t.Fatalf("%v", err)
	}
}

func TestOpenPullRequestValidatesInput(t *testing.T) {
	f := &fakeHost{}
	s := New(f, "https://github.com")
	_, err := s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Head: "h"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("%v", err)
	}
	got, err := s.OpenPullRequest(context.Background(), &pluginv1.OpenPullRequestRequest{Repo: "o/r", Base: "main", Head: "h", Title: "t"})
	if err != nil || got.Number != 1 || got.Url != "https://x/pull/1" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestGetCapabilities(t *testing.T) {
	c, _ := New(&fakeHost{}, "").GetCapabilities(context.Background(), &pluginv1.GetCapabilitiesRequest{})
	if c.ContractVersion != "plugin.v1" || c.AdapterName != "github" || c.SupportsThreads || c.SupportsWebhooks {
		t.Fatalf("%+v", c)
	}
}
