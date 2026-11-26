package github

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"
)

// reviewStub fakes one repo acme/a: issueComments and reviewComments are the JSON arrays of
// the two comment lists, heads maps PR numbers to head branches, reviews maps PR numbers to
// their review list. It records the since parameters it saw.
type reviewStub struct {
	issueComments, reviewComments string
	heads                         map[string]string
	reviews                       map[string]string

	mu     sync.Mutex
	sinces []string
}

func (s *reviewStub) handler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /app/installations/77/access_tokens", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"token":"ghs_read","expires_at":"2026-01-02T04:04:05Z"}`)
	})
	mux.HandleFunc("GET /app", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, `{"slug":"orchivio"}`) })
	list := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer ghs_read" {
				t.Errorf("bad auth %q", r.Header.Get("Authorization"))
			}
			s.mu.Lock()
			s.sinces = append(s.sinces, r.URL.Query().Get("since"))
			s.mu.Unlock()
			io.WriteString(w, body)
		}
	}
	mux.HandleFunc("GET /repos/acme/a/issues/comments", list(s.issueComments))
	mux.HandleFunc("GET /repos/acme/a/pulls/comments", list(s.reviewComments))
	mux.HandleFunc("GET /repos/acme/a/pulls/{n}", func(w http.ResponseWriter, r *http.Request) {
		n := r.PathValue("n")
		io.WriteString(w, `{"number":`+n+`,"html_url":"https://github.com/acme/a/pull/`+n+`","head":{"ref":"`+s.heads[n]+`"}}`)
	})
	mux.HandleFunc("GET /repos/acme/a/pulls/{n}/reviews", func(w http.ResponseWriter, r *http.Request) {
		if body, ok := s.reviews[r.PathValue("n")]; ok {
			io.WriteString(w, body)
			return
		}
		io.WriteString(w, `[]`)
	})
	return mux
}

const (
	alice       = `{"id":11,"login":"alice","type":"User"}`
	botUser     = `{"id":99,"login":"orchivio[bot]","type":"Bot"}`
	otherBot    = `{"id":98,"login":"dependabot[bot]","type":"Bot"}`
	recentStamp = `"2026-01-02T03:04:00Z"`
)

func issueComment(id, pr, user, body string) string {
	return `{"id":` + id + `,"body":"` + body + `","user":` + user + `,"updated_at":` + recentStamp +
		`,"html_url":"https://github.com/acme/a/pull/` + pr + `#issuecomment-` + id +
		`","issue_url":"https://api.github.com/repos/acme/a/issues/` + pr + `"}`
}

// stream polls len(ticks)+1 times (one at start, one per tick) and returns the events.
func stream(t *testing.T, app *App, ticks int) []ReviewEvent {
	t.Helper()
	every := make(chan time.Time)
	var got []ReviewEvent
	done := make(chan error, 1)
	go func() {
		done <- app.StreamReviews(context.Background(), acme, []string{"acme/a"}, every, func(e ReviewEvent) error {
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
		heads: map[string]string{"5": "orchivio/x"},
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
}

func TestStreamSkipsOwnComments(t *testing.T) {
	stub := &reviewStub{
		issueComments:  `[` + issueComment("1", "5", botUser, "done") + `,` + issueComment("2", "5", otherBot, "bump @orchivio") + `]`,
		reviewComments: `[]`,
		heads:          map[string]string{"5": "orchivio/x"},
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
		heads:          map[string]string{"5": "feature/orchivio/x"},
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
		heads:          map[string]string{"5": "orchivio/x"},
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
	if !errors.Is(&apiError{status: http.StatusNotFound}, ErrNotFound) || !errors.Is(&apiError{status: http.StatusUnauthorized}, ErrUnauthenticated) {
		t.Fatal("404/401 must match ErrNotFound/ErrUnauthenticated")
	}
	if errors.Is(&apiError{status: http.StatusInternalServerError}, ErrNotFound) {
		t.Fatal("500 must not match ErrNotFound")
	}
}
