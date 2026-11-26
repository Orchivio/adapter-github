package github

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// reviewStub fakes one repo: pulls is the JSON array of GET /pulls (open, updated desc),
// issueComments and reviewComments the two comment lists, reviews maps PR numbers to their
// review list. failComments makes the first issue comment listing answer 500. It records
// the since parameters of the comment lists and the PRs whose reviews were read.
type reviewStub struct {
	repo                                 string
	pulls, issueComments, reviewComments string
	reviews                              map[string]string
	failComments                         bool

	mu          sync.Mutex
	sinces      []string
	reviewsRead []string
}

func (s *reviewStub) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	tokenRoutes(mux)
	s.register(t, mux)
	return mux
}

func tokenRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /app/installations/77/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"token":"ghs_read","expires_at":"2026-01-02T04:04:05Z"}`)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"slug":"orchivio"}`) })
}

func (s *reviewStub) register(t *testing.T, mux *http.ServeMux) {
	if s.repo == "" {
		s.repo = "acme/a"
	}
	base := "GET /repos/" + s.repo
	list := func(body string, fail bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer ghs_read" {
				t.Errorf("bad auth %q", r.Header.Get("Authorization"))
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			s.sinces = append(s.sinces, r.URL.Query().Get("since"))
			if fail && s.failComments {
				s.failComments = false
				http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
				return
			}
			io.WriteString(w, body)
		}
	}
	mux.HandleFunc(base+"/issues/comments", list(s.issueComments, true))
	mux.HandleFunc(base+"/pulls/comments", list(s.reviewComments, false))
	mux.HandleFunc(base+"/pulls", func(w http.ResponseWriter, r *http.Request) {
		if q := r.URL.Query(); q.Get("state") != "open" || q.Get("sort") != "updated" || q.Get("direction") != "desc" {
			t.Errorf("bad pulls query %q", r.URL.RawQuery)
		}
		io.WriteString(w, s.pulls)
	})
	mux.HandleFunc(base+"/pulls/{n}/reviews", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.reviewsRead = append(s.reviewsRead, r.PathValue("n"))
		s.mu.Unlock()
		if body, ok := s.reviews[r.PathValue("n")]; ok {
			io.WriteString(w, body)
			return
		}
		io.WriteString(w, `[]`)
	})
}

// pull is a PR of acme/a with head ref from headRepo, last updated at stamp (a JSON string).
func pull(n, ref, headRepo, stamp string) string {
	return `{"number":` + n + `,"html_url":"https://github.com/acme/a/pull/` + n + `","updated_at":` + stamp +
		`,"head":{"ref":"` + ref + `","repo":{"full_name":"` + headRepo + `"}}}`
}

const (
	alice       = `{"id":11,"login":"alice","type":"User"}`
	botUser     = `{"id":99,"login":"orchivio[bot]","type":"Bot"}`
	otherBot    = `{"id":98,"login":"dependabot[bot]","type":"Bot"}`
	recentStamp = `"2026-01-02T03:04:00Z"`
	oldStamp    = `"2025-12-01T00:00:00Z"`
)

var orchivioPR5 = `[` + pull("5", "orchivio/x", "acme/a", recentStamp) + `]`

func issueComment(id, pr, user, body string) string {
	return `{"id":` + id + `,"body":"` + body + `","user":` + user + `,"updated_at":` + recentStamp +
		`,"html_url":"https://github.com/acme/a/pull/` + pr + `#issuecomment-` + id +
		`","issue_url":"https://api.github.com/repos/acme/a/issues/` + pr + `"}`
}

// stream polls repos (default acme/a) ticks+1 times (one at start, one per tick) and returns the events.
func stream(t *testing.T, app *App, ticks int, repos ...string) []ReviewEvent {
	t.Helper()
	if len(repos) == 0 {
		repos = []string{"acme/a"}
	}
	every := make(chan time.Time)
	var got []ReviewEvent
	done := make(chan error, 1)
	go func() {
		done <- app.StreamReviews(context.Background(), acme, repos, every, func(e ReviewEvent) error {
			got = append(got, e)
			return nil
		})
	}()
	for range ticks {
		every <- fixedNow
	}
	close(every)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return got
}

func TestStreamEmitsReviewComments(t *testing.T) {
	stub := &reviewStub{
		issueComments: `[` + issueComment("1", "5", alice, "please fix @orchivio[bot]") + `]`,
		reviewComments: `[{"id":2,"body":"rename this","user":` + alice + `,"updated_at":` + recentStamp +
			`,"html_url":"https://github.com/acme/a/pull/5#discussion_r2","pull_request_url":"https://api.github.com/repos/acme/a/pulls/5"}]`,
		pulls: `[` + pull("5", "orchivio/x", "acme/a", recentStamp) + `,` + pull("8", "orchivio/old", "acme/a", oldStamp) + `]`,
		reviews: map[string]string{"5": `[
			{"id":3,"body":"looks off","state":"CHANGES_REQUESTED","user":` + alice + `,"submitted_at":` + recentStamp + `},
			{"id":4,"body":"draft","state":"PENDING","user":` + alice + `},
			{"id":6,"body":"","state":"APPROVED","user":` + alice + `,"submitted_at":` + recentStamp + `},
			{"id":7,"body":"old","state":"COMMENTED","user":` + alice + `,"submitted_at":"2025-12-01T00:00:00Z"}]`},
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	want := []ReviewEvent{
		{ID: "ic:1", Repo: "acme/a", Branch: "orchivio/x", PRURL: "https://github.com/acme/a/pull/5", ActorID: 11, Login: "alice", Body: "please fix @orchivio[bot]", MentionsBot: true},
		{ID: "rc:2", Repo: "acme/a", Branch: "orchivio/x", PRURL: "https://github.com/acme/a/pull/5", ActorID: 11, Login: "alice", Body: "rename this"},
		{ID: "rv:3", Repo: "acme/a", Branch: "orchivio/x", PRURL: "https://github.com/acme/a/pull/5", ActorID: 11, Login: "alice", Body: "looks off"},
	}
	for i := range got {
		got[i].Updated = time.Time{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if since := fixedNow.Add(-2 * time.Minute).Format(time.RFC3339); stub.sinces[0] != since {
		t.Fatalf("since = %q, want %q", stub.sinces[0], since)
	}
	if !slices.Equal(stub.reviewsRead, []string{"5"}) {
		t.Fatalf("reviews read for %v, want only the recently updated PR 5", stub.reviewsRead)
	}
}

func TestStreamEmitsReviewOnlyPR(t *testing.T) {
	stub := &reviewStub{
		pulls:          orchivioPR5,
		issueComments:  `[]`,
		reviewComments: `[]`,
		reviews: map[string]string{"5": `[{"id":3,"body":"summary only","state":"CHANGES_REQUESTED","user":` + alice +
			`,"submitted_at":` + recentStamp + `}]`},
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	if len(got) != 1 || got[0].ID != "rv:3" || got[0].Branch != "orchivio/x" || got[0].Body != "summary only" {
		t.Fatalf("got %+v", got)
	}
}

func TestStreamIgnoresForkPRs(t *testing.T) {
	stub := &reviewStub{
		pulls:          `[` + pull("5", "orchivio/x", "mallory/a", recentStamp) + `]`,
		issueComments:  `[` + issueComment("1", "5", alice, "hi") + `]`,
		reviewComments: `[]`,
		reviews:        map[string]string{"5": `[{"id":3,"body":"r","state":"COMMENTED","user":` + alice + `,"submitted_at":` + recentStamp + `}]`},
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	if len(got) != 0 || len(stub.reviewsRead) != 0 {
		t.Fatalf("got %+v, reviews read %v", got, stub.reviewsRead)
	}
}

func TestStreamSkipsUnmatchableComments(t *testing.T) {
	bogus := `{"id":9,"body":"x","user":` + alice + `,"updated_at":` + recentStamp +
		`,"html_url":"https://github.com/acme/a/pull/zz","issue_url":"garbage"}`
	stub := &reviewStub{
		pulls:          orchivioPR5,
		issueComments:  `[` + bogus + `,` + issueComment("1", "7", alice, "closed pr") + `,` + issueComment("2", "5", alice, "ok") + `]`,
		reviewComments: `[]`,
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	if len(got) != 1 || got[0].ID != "ic:2" {
		t.Fatalf("got %+v", got)
	}
}

func TestStreamFailingRepoKeepsCursorWhileOthersEmit(t *testing.T) {
	const later = `"2026-01-02T05:00:00Z"` // after every cursor of the advancing clock
	good := &reviewStub{repo: "acme/a", pulls: `[` + pull("5", "orchivio/x", "acme/a", later) + `]`,
		issueComments: `[` + strings.ReplaceAll(issueComment("1", "5", alice, "hi"), recentStamp, later) + `]`, reviewComments: `[]`}
	bad := &reviewStub{repo: "acme/b", pulls: `[` + pull("6", "orchivio/y", "acme/b", later) + `]`,
		issueComments: `[]`, reviewComments: `[]`, failComments: true}
	mux := http.NewServeMux()
	tokenRoutes(mux)
	good.register(t, mux)
	bad.register(t, mux)
	app, _ := newTestApp(t, mux)
	var calls atomic.Int64
	app.now = func() time.Time { return fixedNow.Add(time.Duration(calls.Add(1)) * time.Minute) }

	got := stream(t, app, 1, "acme/a", "acme/b")

	if len(got) != 1 || got[0].ID != "ic:1" {
		t.Fatalf("got %+v", got)
	}
	// bad: poll 1 lists issue comments (500), poll 2 lists both lists from the same cursor.
	if len(bad.sinces) != 3 || bad.sinces[0] != bad.sinces[1] {
		t.Fatalf("failing repo sinces %v, want the old cursor again", bad.sinces)
	}
	// good: two lists per poll, the second poll from an advanced cursor.
	if len(good.sinces) != 4 || good.sinces[2] <= good.sinces[0] {
		t.Fatalf("good repo sinces %v, want an advanced cursor", good.sinces)
	}
}

func TestStreamSkipsOwnComments(t *testing.T) {
	stub := &reviewStub{
		issueComments:  `[` + issueComment("1", "5", botUser, "done") + `,` + issueComment("2", "5", otherBot, "bump @orchivio") + `]`,
		reviewComments: `[]`,
		pulls:          orchivioPR5,
		reviews:        map[string]string{"5": `[{"id":3,"body":"self review","state":"COMMENTED","user":` + botUser + `,"submitted_at":` + recentStamp + `}]`},
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	if len(got) != 1 || got[0].ID != "ic:2" || !got[0].MentionsBot {
		t.Fatalf("got %+v", got)
	}
}

func TestStreamSkipsNonOrchivioBranches(t *testing.T) {
	plainIssue := `{"id":8,"body":"issue","user":` + alice + `,"updated_at":` + recentStamp +
		`,"html_url":"https://github.com/acme/a/issues/9#issuecomment-8","issue_url":"https://api.github.com/repos/acme/a/issues/9"}`
	stub := &reviewStub{
		issueComments:  `[` + issueComment("1", "5", alice, "hi") + `,` + plainIssue + `]`,
		reviewComments: `[]`,
		pulls:          `[` + pull("5", "feature/orchivio/x", "acme/a", recentStamp) + `]`,
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 0)

	if len(got) != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestStreamDedupAcrossOverlap(t *testing.T) {
	stub := &reviewStub{
		issueComments:  `[` + issueComment("1", "5", alice, "hi") + `]`,
		reviewComments: `[]`,
		pulls:          orchivioPR5,
	}
	app, _ := newTestApp(t, stub.handler(t))

	got := stream(t, app, 1)

	if len(got) != 1 || got[0].ID != "ic:1" {
		t.Fatalf("got %+v", got)
	}
	if len(stub.sinces) != 4 {
		t.Fatalf("want two polls of two lists, got sinces %v", stub.sinces)
	}
}

func TestStreamRejectsInvalidRepos(t *testing.T) {
	app, _ := newTestApp(t, http.NotFoundHandler())
	err := app.StreamReviews(context.Background(), acme, []string{"not-a-repo"}, nil, nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIErrorStatusMapsToSentinels(t *testing.T) {
	if !errors.Is(&apiError{status: http.StatusNotFound}, ErrNotFound) {
		t.Fatal("404 must match ErrNotFound")
	}
	if errors.Is(&apiError{status: http.StatusInternalServerError}, ErrNotFound) {
		t.Fatal("500 must not match ErrNotFound")
	}
}

func TestStreamMintsOneCachedTokenPerOwner(t *testing.T) {
	a := &reviewStub{repo: "acme/a", pulls: `[]`}
	b := &reviewStub{repo: "acme/b", pulls: `[]`}
	mux := http.NewServeMux()
	var mints atomic.Int32
	var bodies []tokenReq
	mux.HandleFunc("POST /app/installations/77/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		mints.Add(1)
		var tr tokenReq
		_ = json.NewDecoder(r.Body).Decode(&tr)
		bodies = append(bodies, tr)
		io.WriteString(w, `{"token":"ghs_read","expires_at":"2026-01-02T04:04:05Z"}`)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"slug":"orchivio"}`) })
	a.register(t, mux)
	b.register(t, mux)
	app, _ := newTestApp(t, mux)

	stream(t, app, 2, "acme/a", "acme/b")

	if mints.Load() != 1 || bodies[0].Repositories != nil || bodies[0].Permissions["pull_requests"] != "read" {
		t.Fatalf("mints = %d, bodies = %+v; want one owner-wide read token", mints.Load(), bodies)
	}
}

func TestReviewTokenRemintsShortlyBeforeExpiry(t *testing.T) {
	var got []tokenReq
	var mints atomic.Int32
	app, _ := newTestApp(t, githubStub(t, &got, &mints))
	tokens := map[string]cachedToken{}
	if _, err := app.reviewToken(context.Background(), acme, "acme", tokens); err != nil {
		t.Fatal(err)
	}
	app.now = func() time.Time { return time.Date(2026, 1, 2, 4, 0, 0, 0, time.UTC) } // 4m before expiry

	tok, err := app.reviewToken(context.Background(), acme, "ACME", tokens)

	if err != nil || tok != "ghs_tok" || mints.Load() != 2 {
		t.Fatalf("tok=%q err=%v mints=%d", tok, err, mints.Load())
	}
}
