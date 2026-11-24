package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

const perPage = 100

var (
	// ErrPendingApproval marks an install request a non-owner sent to an organization owner.
	ErrPendingApproval = errors.New("installation pending approval by an organization owner")
	// ErrAccessDenied marks an installation the authorizing GitHub user cannot access.
	ErrAccessDenied = errors.New("github user has no access to this installation")
)

// BeginConnect returns the App's install page; GitHub sends state back to the callback.
func (a *App) BeginConnect(ctx context.Context, state string) (string, error) {
	if state == "" {
		return "", fmt.Errorf("%w: state required", ErrInvalidInput)
	}
	slug, err := a.appSlug(ctx)
	if err != nil {
		return "", err
	}
	return a.webURL + "/apps/" + url.PathEscape(slug) + "/installations/new?" + url.Values{"state": {state}}.Encode(), nil
}

func (a *App) appSlug(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock() // ponytail: holds the lock across one HTTP call, only until the first success
	if a.slug != "" {
		return a.slug, nil
	}
	jwt, err := a.jwt()
	if err != nil {
		return "", err
	}
	var out struct{ Slug string }
	if err := a.do(ctx, http.MethodGet, "/app", jwt, nil, &out); err != nil {
		return "", err
	}
	if out.Slug == "" {
		return "", errors.New("GitHub API: app has no slug")
	}
	a.slug = out.Slug
	return a.slug, nil
}

// CompleteConnect handles the install callback: it proves via the user's OAuth code that
// the user can access installation_id, then returns that installation. The user token is
// used for that one check only and dropped.
func (a *App) CompleteConnect(ctx context.Context, redirectURI string, query map[string]string) (Installation, error) {
	rawID := query["installation_id"]
	if rawID == "" {
		return Installation{}, ErrPendingApproval
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		return Installation{}, fmt.Errorf("%w: invalid installation_id", ErrInvalidInput)
	}
	if query["code"] == "" {
		return Installation{}, fmt.Errorf("%w: code required", ErrInvalidInput)
	}
	userToken, err := a.exchangeCode(ctx, redirectURI, query["code"])
	if err != nil {
		return Installation{}, err
	}
	visible, err := listAll[struct{ ID int64 }](ctx, a, "/user/installations", "installations", userToken)
	if err != nil {
		return Installation{}, err
	}
	if !slices.ContainsFunc(visible, func(i struct{ ID int64 }) bool { return i.ID == id }) {
		return Installation{}, ErrAccessDenied
	}
	jwt, err := a.jwt()
	if err != nil {
		return Installation{}, err
	}
	var inst struct {
		Account struct{ Login string }
	}
	if err := a.do(ctx, http.MethodGet, fmt.Sprintf("/app/installations/%d", id), jwt, nil, &inst); err != nil {
		return Installation{}, err
	}
	return Installation{ID: id, Account: inst.Account.Login}, nil
}

// exchangeCode trades the OAuth code for a user token. Errors carry GitHub's error code only.
func (a *App) exchangeCode(ctx context.Context, redirectURI, code string) (string, error) {
	form := url.Values{"client_id": {a.clientID}, "client_secret": {a.clientSecret}, "code": {code}, "redirect_uri": {redirectURI}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webURL+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("build oauth request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token exchange: %w", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out); err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth token exchange: status %d", resp.StatusCode)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("%w: oauth code rejected: %s", ErrInvalidInput, out.Error)
	}
	return out.AccessToken, nil
}

// CheckAccess returns the repos ("owner/name") no installation covers. Each installation's
// repo list is fetched at most once per call.
func (a *App) CheckAccess(ctx context.Context, installs []Installation, repos []string) ([]string, error) {
	type repo struct {
		FullName string `json:"full_name"`
	}
	listed := map[int64][]repo{}
	var denied []string
	for _, r := range repos {
		owner, _, err := parseRepos([]string{r})
		if err != nil {
			denied = append(denied, r)
			continue
		}
		inst, err := pick(installs, owner)
		if err != nil {
			denied = append(denied, r)
			continue
		}
		if _, ok := listed[inst.ID]; !ok {
			tok, _, err := a.accessToken(ctx, inst.ID, map[string]any{"permissions": map[string]string{"metadata": "read"}})
			if err != nil {
				return nil, err
			}
			if listed[inst.ID], err = listAll[repo](ctx, a, "/installation/repositories", "repositories", tok); err != nil {
				return nil, err
			}
		}
		if !slices.ContainsFunc(listed[inst.ID], func(x repo) bool { return strings.EqualFold(x.FullName, r) }) {
			denied = append(denied, r)
		}
	}
	return denied, nil
}

// listAll pages through a GitHub list response {"total_count":n,"<key>":[...]}.
func listAll[T any](ctx context.Context, a *App, path, key, bearer string) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		var out map[string]json.RawMessage
		if err := a.do(ctx, http.MethodGet, fmt.Sprintf("%s?per_page=%d&page=%d", path, perPage, page), bearer, nil, &out); err != nil {
			return nil, err
		}
		var items []T
		if raw, ok := out[key]; ok {
			if err := json.Unmarshal(raw, &items); err != nil {
				return nil, fmt.Errorf("decode github %s: %w", key, err)
			}
		}
		all = append(all, items...)
		if len(items) < perPage {
			return all, nil
		}
	}
}
