// Package github talks to the GitHub REST API as a GitHub App.
package github

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	maxBody      = 1 << 20
	HTTPTimeout  = 30 * time.Second
	jwtBackdate  = 60 * time.Second
	jwtLifetime  = 9 * time.Minute
	apiVersion   = "2022-11-28"
	acceptHeader = "application/vnd.github+json"
)

var (
	// ErrInvalidInput marks caller errors (bad repo list etc.).
	ErrInvalidInput = errors.New("invalid input")
	// ErrNotInstalled marks a repo owner without a connected installation in the credentials.
	ErrNotInstalled = errors.New("no connected installation")

	repoPattern = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)
)

// NotInstalledError carries the owner without any GitHub response detail.
type NotInstalledError struct{ Owner string }

func (e *NotInstalledError) Error() string        { return "no connected installation for owner " + e.Owner }
func (e *NotInstalledError) Is(target error) bool { return target == ErrNotInstalled }

// Config configures one GitHub App. WebURL hosts the install page and the OAuth
// token endpoint (https://github.com); a nil HTTP gets a client with a 30s timeout.
type Config struct {
	APIURL, WebURL         string
	AppID                  int64
	Key                    *rsa.PrivateKey
	ClientID, ClientSecret string
	Now                    func() time.Time
	HTTP                   *http.Client
}

// App mints installation tokens, opens pull requests and connects installations for one
// GitHub App. It keeps no per-tenant state: installations arrive with every call.
type App struct {
	apiURL, webURL         string
	appID                  int64
	key                    *rsa.PrivateKey
	clientID, clientSecret string
	now                    func() time.Time
	hc                     *http.Client

	mu   sync.Mutex
	slug string // App slug from GET /app, fetched once
}

// NewApp builds an App from c.
func NewApp(c Config) *App {
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: HTTPTimeout}
	}
	return &App{apiURL: strings.TrimRight(c.APIURL, "/"), webURL: strings.TrimRight(c.WebURL, "/"),
		appID: c.AppID, key: c.Key, clientID: c.ClientID, clientSecret: c.ClientSecret, now: c.Now, hc: hc}
}

// Installation is the per-tenant access record stored as Credential.data.
type Installation struct {
	ID      int64  `json:"installationId"`
	Account string `json:"account"`
}

// ParseInstallation decodes Credential.data; errors never echo the data.
func ParseInstallation(data []byte) (Installation, error) {
	var i Installation
	if err := json.Unmarshal(data, &i); err != nil || i.ID <= 0 || i.Account == "" {
		return Installation{}, fmt.Errorf("%w: malformed credential", ErrInvalidInput)
	}
	return i, nil
}

// pick returns the installation whose account owns the repo (case-insensitive).
func pick(installs []Installation, owner string) (Installation, error) {
	for _, i := range installs {
		if strings.EqualFold(i.Account, owner) {
			return i, nil
		}
	}
	return Installation{}, &NotInstalledError{Owner: owner}
}

// ParsePrivateKey parses a PKCS#1 or PKCS#8 RSA PEM. Errors never contain key material.
func ParsePrivateKey(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("private key: no PEM block found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key: not a valid PKCS#1 or PKCS#8 key")
	}
	k, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key: not an RSA key")
	}
	return k, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *App) jwt() (string, error) {
	now := a.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-jwtBackdate).Unix(),
		"exp": now.Add(jwtLifetime).Unix(),
		"iss": fmt.Sprint(a.appID),
	})
	signing := b64(hdr) + "." + b64(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signing + "." + b64(sig), nil
}

// parseRepos validates "owner/name" entries: same owner, deduped, at least one.
func parseRepos(repos []string) (owner string, names []string, err error) {
	if len(repos) == 0 {
		return "", nil, fmt.Errorf("%w: at least one repo required", ErrInvalidInput)
	}
	seen := map[string]bool{}
	for _, r := range repos {
		if !repoPattern.MatchString(r) || strings.Contains(r, "..") {
			return "", nil, fmt.Errorf("%w: invalid repo %q", ErrInvalidInput, r)
		}
		o, n, _ := strings.Cut(r, "/")
		if owner == "" {
			owner = o
		} else if !strings.EqualFold(owner, o) {
			return "", nil, fmt.Errorf("%w: repos must share one owner", ErrInvalidInput)
		}
		if k := strings.ToLower(n); !seen[k] {
			seen[k] = true
			names = append(names, n)
		}
	}
	return owner, names, nil
}

// do performs a request; non-2xx becomes an error with status and GitHub's message only.
func (a *App) do(ctx context.Context, method, path, bearer string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.apiURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", acceptHeader)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	req.Header.Set("Authorization", "Bearer "+bearer)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return fmt.Errorf("github request %s: %w", method, errors.Unwrap(err)) // drops URL-bearing wrapper
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return fmt.Errorf("read github response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Message string
			Errors  []struct{ Message string }
		}
		_ = json.Unmarshal(data, &e)
		msg := e.Message
		for _, d := range e.Errors { // validation details, e.g. "not all refs are readable"
			if d.Message != "" {
				msg += ": " + d.Message
			}
		}
		return &apiError{status: resp.StatusCode, message: msg}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode github response: %w", err)
	}
	return nil
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return fmt.Sprintf("GitHub API %d: %s", e.status, e.message) }

func (a *App) mint(ctx context.Context, installs []Installation, repos []string, perms map[string]string) (string, time.Time, error) {
	owner, names, err := parseRepos(repos)
	if err != nil {
		return "", time.Time{}, err
	}
	inst, err := pick(installs, owner)
	if err != nil {
		return "", time.Time{}, err
	}
	return a.accessToken(ctx, inst.ID, map[string]any{"repositories": names, "permissions": perms})
}

func (a *App) accessToken(ctx context.Context, id int64, body map[string]any) (string, time.Time, error) {
	jwt, err := a.jwt()
	if err != nil {
		return "", time.Time{}, err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.do(ctx, http.MethodPost, fmt.Sprintf("/app/installations/%d/access_tokens", id), jwt, body, &out); err != nil {
		return "", time.Time{}, err
	}
	return out.Token, out.ExpiresAt, nil
}

// InstallationToken mints a fresh token limited to repos (all one owner).
// write=true grants contents:write only; PRs need OpenPullRequest's own token.
// ponytail: no caching; cache per (installation, repos, perms) until expiry-5m if rate limits bite.
func (a *App) InstallationToken(ctx context.Context, installs []Installation, repos []string, write bool) (string, time.Time, error) {
	contents := "read"
	if write {
		contents = "write"
	}
	return a.mint(ctx, installs, repos, map[string]string{"contents": contents, "metadata": "read"})
}

type pullRequest struct {
	HTMLURL string `json:"html_url"`
	Number  int64  `json:"number"`
}

// OpenPullRequest opens a PR using a token scoped to this single repo with pull_requests:write
// and contents:read (GitHub must read head and base, else 422 "not all refs are readable").
// A follow-up run pushes to the same branch again; GitHub then answers 422 and the already
// open PR for that head is returned instead.
func (a *App) OpenPullRequest(ctx context.Context, installs []Installation, repo, base, head, title, body string) (string, int64, error) {
	owner, _, err := parseRepos([]string{repo})
	if err != nil {
		return "", 0, err
	}
	tok, _, err := a.mint(ctx, installs, []string{repo}, map[string]string{"pull_requests": "write", "contents": "read", "metadata": "read"})
	if err != nil {
		return "", 0, err
	}
	var out pullRequest
	err = a.do(ctx, http.MethodPost, "/repos/"+repo+"/pulls", tok,
		map[string]string{"title": title, "head": head, "base": base, "body": body}, &out)
	var ae *apiError
	if errors.As(err, &ae) && ae.status == http.StatusUnprocessableEntity {
		var open []pullRequest
		q := url.Values{"head": {owner + ":" + head}, "state": {"open"}}
		if lerr := a.do(ctx, http.MethodGet, "/repos/"+repo+"/pulls?"+q.Encode(), tok, nil, &open); lerr == nil && len(open) > 0 {
			return open[0].HTMLURL, open[0].Number, nil
		}
		return "", 0, err
	}
	if err != nil {
		return "", 0, err
	}
	return out.HTMLURL, out.Number, nil
}
