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
	HTMLURL   string    `json:"html_url"`
	UpdatedAt time.Time `json:"updated_at"`
	Number    int64     `json:"number"`
	Head      struct {
		Ref  string `json:"ref"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
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
	var b botMatcher
	seen := map[string]time.Time{} // id -> updated; pruned once older than every window
	for {
		if b.mention == nil {
			b = a.newBotMatcher(ctx)
		}
		if b.mention != nil {
			for _, e := range a.pollReviews(ctx, installs, repos, cursors, b) {
				if _, dup := seen[e.ID]; dup {
					continue
				}
				if err := send(e); err != nil {
					return err
				}
				seen[e.ID] = e.Updated
			}
			prune(seen, cursors)
		}
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

// botMatcher recognizes the App's own comments and mentions of it; built once per stream.
type botMatcher struct {
	slug    string
	mention *regexp.Regexp
}

// newBotMatcher fetches the App slug; on failure it logs and returns a zero matcher, retried next poll.
func (a *App) newBotMatcher(ctx context.Context) botMatcher {
	slug, err := a.appSlug(ctx)
	if err != nil {
		if ctx.Err() == nil {
			slog.Warn("review poll: app slug", "err", err.Error())
		}
		return botMatcher{}
	}
	return botMatcher{slug: slug, mention: regexp.MustCompile(`(?i)@` + regexp.QuoteMeta(slug) + `(\[bot\])?([^A-Za-z0-9-]|$)`)}
}

// isOwn reports whether u is this App's bot user.
func (b botMatcher) isOwn(u ghUser) bool {
	return u.Type == "Bot" && strings.EqualFold(u.Login, b.slug+"[bot]")
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
func (a *App) pollReviews(ctx context.Context, installs []Installation, repos []string, cursors map[string]time.Time, b botMatcher) []ReviewEvent {
	var out []ReviewEvent
	for _, repo := range repos {
		next := a.now()
		tok, _, err := a.mint(ctx, installs, []string{repo}, reviewPerms)
		if err == nil {
			var events []ReviewEvent
			events, err = a.repoReviews(ctx, tok, b, repo, cursors[repo].Add(-reviewOverlap))
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

// repoReviews returns the events of one repo updated (reviews: submitted) since, on its open
// orchivio/ PRs updated since. Comments and reviews bump a PR's updated_at, so this set
// also finds a review submitted without any comment.
func (a *App) repoReviews(ctx context.Context, tok string, b botMatcher, repo string, since time.Time) ([]ReviewEvent, error) {
	pulls, err := a.orchivioPulls(ctx, tok, repo, since)
	if err != nil || len(pulls) == 0 {
		return nil, err
	}
	issueComments, err := listSince[ghComment](ctx, a, "/repos/"+repo+"/issues/comments", since, tok)
	if err != nil {
		return nil, err
	}
	reviewComments, err := listSince[ghComment](ctx, a, "/repos/"+repo+"/pulls/comments", since, tok)
	if err != nil {
		return nil, err
	}
	var out []ReviewEvent
	add := func(prefix string, id int64, pr ghPull, u ghUser, body string, updated time.Time) {
		if b.isOwn(u) {
			return
		}
		out = append(out, ReviewEvent{ID: prefix + strconv.FormatInt(id, 10), Repo: repo, Branch: pr.Head.Ref, PRURL: pr.HTMLURL,
			ActorID: u.ID, Login: u.Login, Body: body, MentionsBot: b.mention.MatchString(body), Updated: updated})
	}
	comment := func(prefix string, c ghComment, prURL string) {
		pr, ok := pulls[lastSegment(prURL)]
		if !ok { // plain issue, other PR, or unparsable URL
			slog.Debug("review poll: comment not on a tracked PR", "repo", repo, "id", prefix+strconv.FormatInt(c.ID, 10))
			return
		}
		add(prefix, c.ID, pr, c.User, c.Body, c.UpdatedAt)
	}
	for _, c := range issueComments {
		comment("ic:", c, c.IssueURL)
	}
	for _, c := range reviewComments {
		comment("rc:", c, c.PullURL)
	}
	for number, pr := range pulls {
		var reviews []ghReview // ponytail: first page (100) only; page like listSince if PRs get more reviews
		if err := a.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/pulls/%s/reviews?per_page=%d", repo, number, perPage), tok, nil, &reviews); err != nil {
			return nil, err
		}
		for _, r := range reviews {
			if r.State != reviewPending && r.Body != "" && !r.SubmittedAt.Before(since) {
				add("rv:", r.ID, pr, r.User, r.Body, r.SubmittedAt)
			}
		}
	}
	return out, nil
}

// orchivioPulls returns, by number, the open PRs of repo updated since whose head branch
// starts with "orchivio/" and lives in repo itself (fork PRs are ignored).
func (a *App) orchivioPulls(ctx context.Context, tok, repo string, since time.Time) (map[string]ghPull, error) {
	out := map[string]ghPull{}
	for page := 1; ; page++ {
		q := url.Values{"state": {"open"}, "sort": {"updated"}, "direction": {"desc"},
			"per_page": {strconv.Itoa(perPage)}, "page": {strconv.Itoa(page)}}
		var pulls []ghPull
		if err := a.do(ctx, http.MethodGet, "/repos/"+repo+"/pulls?"+q.Encode(), tok, nil, &pulls); err != nil {
			return nil, err
		}
		for _, pr := range pulls {
			if pr.UpdatedAt.Before(since) {
				return out, nil
			}
			if strings.HasPrefix(pr.Head.Ref, branchPrefix) && strings.EqualFold(pr.Head.Repo.FullName, repo) {
				out[strconv.FormatInt(pr.Number, 10)] = pr
			}
		}
		if len(pulls) < perPage {
			return out, nil
		}
	}
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
