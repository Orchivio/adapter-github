package github

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	// reviewOverlap re-reads a window before each repo's cursor so comments written
	// while a poll ran are not missed; seen ids are dropped again.
	reviewOverlap = 2 * time.Minute
	branchPrefix  = "orchivio/"
	reviewPending = "PENDING"
)

var reviewPerms = map[string]string{"pull_requests": "read", "metadata": "read"}

// ReviewEvent is a human comment or review on a pull request whose head branch starts
// with "orchivio/". ID is the dedup key: "ic:<id>" (conversation comment), "rc:<id>"
// (inline review comment) or "rv:<id>" (review).
type ReviewEvent struct {
	ID, Repo, Branch, PRURL string
	ActorID                 int64
	Login                   string
	Body                    string
	MentionsBot             bool
	Updated                 time.Time
}

type ghUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Type  string `json:"type"`
}

type ghComment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	User      ghUser    `json:"user"`
	HTMLURL   string    `json:"html_url"`
	IssueURL  string    `json:"issue_url"`
	PullURL   string    `json:"pull_request_url"`
	UpdatedAt time.Time `json:"updated_at"`
}

type ghReview struct {
	ID          int64     `json:"id"`
	Body        string    `json:"body"`
	State       string    `json:"state"`
	User        ghUser    `json:"user"`
	SubmittedAt time.Time `json:"submitted_at"`
}

type ghPull struct {
	HTMLURL string `json:"html_url"`
	Head    struct {
		Ref string `json:"ref"`
	} `json:"head"`
}

// StreamReviews polls repos once now and once per value from every, until ctx ends or
// every is closed, and sends each new ReviewEvent once. Each repo keeps its own cursor,
// advanced only after a successful poll; failures are logged and retried next poll, so
// one deleted repo does not stop the others. The App's own comments are dropped.
func (a *App) StreamReviews(ctx context.Context, installs []Installation, repos []string, every <-chan time.Time, send func(ReviewEvent) error) error {
	if len(repos) == 0 {
		return fmt.Errorf("%w: at least one repo required", ErrInvalidInput)
	}
	cursors := make(map[string]time.Time, len(repos))
	for _, r := range repos {
		if _, _, err := parseRepos([]string{r}); err != nil {
			return err
		}
		cursors[r] = a.now()
	}
	seen := map[string]time.Time{} // id -> updated; pruned once older than every window
	for {
		for _, e := range a.pollReviews(ctx, installs, cursors) {
			if _, dup := seen[e.ID]; dup {
				continue
			}
			if err := send(e); err != nil {
				return err
			}
			seen[e.ID] = e.Updated
		}
		prune(seen, cursors)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case _, ok := <-every:
			if !ok {
				return nil
			}
		}
	}
}

// prune forgets ids updated before the oldest window; they cannot be listed again unedited.
func prune(seen, cursors map[string]time.Time) {
	var oldest time.Time
	for _, c := range cursors {
		if oldest.IsZero() || c.Before(oldest) {
			oldest = c
		}
	}
	for id, updated := range seen {
		if updated.Before(oldest.Add(-reviewOverlap)) {
			delete(seen, id)
		}
	}
}

// pollReviews fetches every repo from its cursor minus the overlap.
// ponytail: one token per repo and poll; mint per owner and cache until expiry if rate limits bite.
func (a *App) pollReviews(ctx context.Context, installs []Installation, cursors map[string]time.Time) []ReviewEvent {
	slug, err := a.appSlug(ctx)
	if err != nil {
		slog.Warn("review poll: app slug", "err", err.Error())
		return nil
	}
	mention := regexp.MustCompile(`(?i)@` + regexp.QuoteMeta(slug) + `(\[bot\])?([^A-Za-z0-9-]|$)`)
	var out []ReviewEvent
	for repo, cursor := range cursors {
		next := a.now()
		tok, _, err := a.mint(ctx, installs, []string{repo}, reviewPerms)
		if err == nil {
			var events []ReviewEvent
			events, err = a.repoReviews(ctx, tok, slug, mention, repo, cursor.Add(-reviewOverlap))
			out = append(out, events...)
		}
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("review poll failed", "repo", repo, "err", err.Error())
			}
			continue
		}
		cursors[repo] = next
	}
	return out
}

// repoReviews returns the events of one repo updated (reviews: submitted) since.
func (a *App) repoReviews(ctx context.Context, tok, slug string, mention *regexp.Regexp, repo string, since time.Time) ([]ReviewEvent, error) {
	issueComments, err := listSince[ghComment](ctx, a, "/repos/"+repo+"/issues/comments", since, tok)
	if err != nil {
		return nil, err
	}
	reviewComments, err := listSince[ghComment](ctx, a, "/repos/"+repo+"/pulls/comments", since, tok)
	if err != nil {
		return nil, err
	}
	pulls := map[string]*ghPull{} // PR number -> PR on an orchivio/ branch, nil otherwise
	var out []ReviewEvent
	add := func(prefix string, id int64, number string, u ghUser, body string, updated time.Time) error {
		pr, err := a.orchivioPull(ctx, tok, repo, number, pulls)
		if err != nil || pr == nil || isOwn(u, slug) {
			return err
		}
		out = append(out, ReviewEvent{ID: prefix + strconv.FormatInt(id, 10), Repo: repo, Branch: pr.Head.Ref, PRURL: pr.HTMLURL,
			ActorID: u.ID, Login: u.Login, Body: body, MentionsBot: mention.MatchString(body), Updated: updated})
		return nil
	}
	for _, c := range issueComments {
		if !strings.Contains(c.HTMLURL, "/pull/") { // comment on a plain issue
			continue
		}
		if err := add("ic:", c.ID, lastSegment(c.IssueURL), c.User, c.Body, c.UpdatedAt); err != nil {
			return nil, err
		}
	}
	for _, c := range reviewComments {
		if err := add("rc:", c.ID, lastSegment(c.PullURL), c.User, c.Body, c.UpdatedAt); err != nil {
			return nil, err
		}
	}
	for number, pr := range pulls {
		if pr == nil {
			continue
		}
		var reviews []ghReview // ponytail: first page (100) only; page like listSince if PRs get more reviews
		if err := a.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%s/reviews?per_page=%d", repo, number, perPage), tok, nil, &reviews); err != nil {
			return nil, err
		}
		for _, r := range reviews {
			if r.State == reviewPending || r.Body == "" || r.SubmittedAt.Before(since) {
				continue
			}
			if err := add("rv:", r.ID, number, r.User, r.Body, r.SubmittedAt); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// orchivioPull returns PR number of repo if its head branch starts with "orchivio/", else nil;
// pulls caches the answers for one poll.
func (a *App) orchivioPull(ctx context.Context, tok, repo, number string, pulls map[string]*ghPull) (*ghPull, error) {
	if pr, ok := pulls[number]; ok {
		return pr, nil
	}
	if _, err := strconv.ParseInt(number, 10, 64); err != nil {
		return nil, fmt.Errorf("github: unexpected pull request url in %s", repo)
	}
	var pr ghPull
	if err := a.do(ctx, http.MethodGet, "/repos/"+repo+"/pulls/"+number, tok, nil, &pr); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(pr.Head.Ref, branchPrefix) {
		pulls[number] = nil
		return nil, nil
	}
	pulls[number] = &pr
	return &pr, nil
}

// isOwn reports whether u is this App's bot user.
func isOwn(u ghUser, slug string) bool {
	return u.Type == "Bot" && strings.EqualFold(u.Login, slug+"[bot]")
}

func lastSegment(u string) string { return u[strings.LastIndex(u, "/")+1:] }

// listSince pages through a plain JSON array list filtered by since.
func listSince[T any](ctx context.Context, a *App, path string, since time.Time, bearer string) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		q := url.Values{"since": {since.UTC().Format(time.RFC3339)}, "per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		var items []T
		if err := a.do(ctx, http.MethodGet, path+"?"+q.Encode(), bearer, nil, &items); err != nil {
			return nil, err
		}
		all = append(all, items...)
		if len(items) < perPage {
			return all, nil
		}
	}
}
