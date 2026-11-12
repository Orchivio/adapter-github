// Package server implements the CodeHostAdapter gRPC service on top of GitHub.
package server

import (
	"context"
	"errors"
	"time"

	pluginv1 "github.com/orchivio/orchestrator/contract/gen/orchivio/plugin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/orchivio/adapter-github/internal/github"
)

const tokenUsername = "x-access-token"

// Host is the GitHub App behaviour the server needs.
type Host interface {
	InstallationToken(ctx context.Context, repos []string, write bool) (string, time.Time, error)
	OpenPullRequest(ctx context.Context, repo, base, head, title, body string) (string, int64, error)
}

// Server implements pluginv1.CodeHostAdapterServer.
type Server struct {
	pluginv1.UnimplementedCodeHostAdapterServer
	host      Host
	cloneBase string
}

// New builds a Server; cloneBase is e.g. "https://github.com".
func New(host Host, cloneBase string) *Server { return &Server{host: host, cloneBase: cloneBase} }

func (s *Server) GetCapabilities(context.Context, *pluginv1.GetCapabilitiesRequest) (*pluginv1.Capabilities, error) {
	return &pluginv1.Capabilities{ContractVersion: "plugin.v1", AdapterName: "github"}, nil
}

func (s *Server) IssueRepoCredentials(ctx context.Context, req *pluginv1.IssueRepoCredentialsRequest) (*pluginv1.RepoCredentials, error) {
	token, exp, err := s.host.InstallationToken(ctx, req.GetRepos(), req.GetWrite())
	if err != nil {
		return nil, toStatus(err)
	}
	urls := make(map[string]string, len(req.GetRepos()))
	for _, r := range req.GetRepos() {
		urls[r] = s.cloneBase + "/" + r + ".git"
	}
	return &pluginv1.RepoCredentials{Username: tokenUsername, Token: token, ExpiresAt: timestamppb.New(exp), CloneUrls: urls}, nil
}

func (s *Server) OpenPullRequest(ctx context.Context, req *pluginv1.OpenPullRequestRequest) (*pluginv1.PullRequest, error) {
	if req.GetRepo() == "" || req.GetBase() == "" || req.GetHead() == "" || req.GetTitle() == "" {
		return nil, status.Error(codes.InvalidArgument, "repo, base, head and title are required")
	}
	url, n, err := s.host.OpenPullRequest(ctx, req.GetRepo(), req.GetBase(), req.GetHead(), req.GetTitle(), req.GetBody())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pluginv1.PullRequest{Url: url, Number: n}, nil
}

// toStatus maps: invalid input -> InvalidArgument, missing installation -> NotFound,
// everything else (GitHub 4xx/5xx, network) -> Unavailable. Messages come from our own
// error types, which carry only status and GitHub's message, never tokens.
func toStatus(err error) error {
	var ni *github.NotInstalledError
	switch {
	case errors.As(err, &ni):
		return status.Error(codes.NotFound, ni.Error())
	case errors.Is(err, github.ErrNotInstalled):
		return status.Error(codes.NotFound, "GitHub App not installed")
	case errors.Is(err, github.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Unavailable, err.Error())
	}
}
