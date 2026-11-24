// Package server implements the CodeHostAdapter gRPC service on top of GitHub.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
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
	InstallationToken(ctx context.Context, installs []github.Installation, repos []string, write bool) (string, time.Time, error)
	OpenPullRequest(ctx context.Context, installs []github.Installation, repo, base, head, title, body string) (string, int64, error)
	BeginConnect(ctx context.Context, state string) (string, error)
	CompleteConnect(ctx context.Context, redirectURI string, query map[string]string) (github.Installation, error)
	CheckAccess(ctx context.Context, installs []github.Installation, repos []string) ([]string, error)
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
	installs, err := installations(req.GetCredentials())
	if err != nil {
		return nil, err
	}
	token, exp, err := s.host.InstallationToken(ctx, installs, req.GetRepos(), req.GetWrite())
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
	installs, err := installations(req.GetCredentials())
	if err != nil {
		return nil, err
	}
	url, n, err := s.host.OpenPullRequest(ctx, installs, req.GetRepo(), req.GetBase(), req.GetHead(), req.GetTitle(), req.GetBody())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pluginv1.PullRequest{Url: url, Number: n}, nil
}

func (s *Server) BeginConnect(ctx context.Context, req *pluginv1.BeginConnectRequest) (*pluginv1.BeginConnectResponse, error) {
	url, err := s.host.BeginConnect(ctx, req.GetState())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pluginv1.BeginConnectResponse{Url: url}, nil
}

func (s *Server) CompleteConnect(ctx context.Context, req *pluginv1.CompleteConnectRequest) (*pluginv1.CompleteConnectResponse, error) {
	inst, err := s.host.CompleteConnect(ctx, req.GetRedirectUri(), req.GetQuery())
	if err != nil {
		return nil, toStatus(err)
	}
	data, _ := json.Marshal(inst) // plain struct, cannot fail
	return &pluginv1.CompleteConnectResponse{
		Credential: &pluginv1.Credential{Data: data},
		Label:      inst.Account,
		ExternalId: strconv.FormatInt(inst.ID, 10),
	}, nil
}

// RefreshCredential returns the record unchanged: it holds no token that expires.
func (s *Server) RefreshCredential(_ context.Context, req *pluginv1.RefreshCredentialRequest) (*pluginv1.Credential, error) {
	return &pluginv1.Credential{Data: req.GetCredential().GetData()}, nil
}

// Disconnect does nothing: Orchivio only forgets the installation; it stays on GitHub.
func (s *Server) Disconnect(context.Context, *pluginv1.DisconnectRequest) (*pluginv1.DisconnectResponse, error) {
	return &pluginv1.DisconnectResponse{}, nil
}

// CheckAccess denies every repo without credentials: nothing is connected.
func (s *Server) CheckAccess(ctx context.Context, req *pluginv1.CheckAccessRequest) (*pluginv1.CheckAccessResponse, error) {
	if len(req.GetCredentials()) == 0 {
		return &pluginv1.CheckAccessResponse{Denied: req.GetItems()}, nil
	}
	installs, err := installations(req.GetCredentials())
	if err != nil {
		return nil, err
	}
	denied, err := s.host.CheckAccess(ctx, installs, req.GetItems())
	if err != nil {
		return nil, toStatus(err)
	}
	return &pluginv1.CheckAccessResponse{Denied: denied}, nil
}

// installations decodes the tenant's credentials; none or malformed -> InvalidArgument.
func installations(creds []*pluginv1.Credential) ([]github.Installation, error) {
	if len(creds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "credentials required")
	}
	out := make([]github.Installation, 0, len(creds))
	for _, c := range creds {
		inst, err := github.ParseInstallation(c.GetData())
		if err != nil {
			return nil, toStatus(err)
		}
		out = append(out, inst)
	}
	return out, nil
}

// toStatus maps: invalid input -> InvalidArgument, owner without connected installation and
// pending install request -> FailedPrecondition, user without access -> PermissionDenied,
// everything else (GitHub 4xx/5xx, network) -> Unavailable. Messages come from our own
// error types, which carry only status and GitHub's message, never tokens.
func toStatus(err error) error {
	switch {
	case errors.Is(err, github.ErrNotInstalled), errors.Is(err, github.ErrPendingApproval):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, github.ErrAccessDenied):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, github.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Unavailable, err.Error())
	}
}
