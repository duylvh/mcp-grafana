package mcpgrafana

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRefresh is a refresh command that records each run and, unless it is
// set to fail, writes a valid session holding newCookie.
type fakeRefresh struct {
	argv  []string
	count string
}

func newFakeRefresh(t *testing.T, sessionPath, origin, newCookie string, fail bool, delay string) *fakeRefresh {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake refresh command is a POSIX shell script")
	}
	dir := t.TempDir()
	count := filepath.Join(dir, "runs")
	script := filepath.Join(dir, "refresh.sh")
	body := fmt.Sprintf("#!/bin/sh\necho run >> %q\nsleep %s\n", count, delay)
	if fail {
		body += "exit 1\n"
	} else {
		body += fmt.Sprintf("printf '%%s' '%s' > %q.tmp && chmod 600 %q.tmp && mv %q.tmp %q\n",
			sessionJSON(origin, newCookie, time.Now().Add(time.Hour)), sessionPath, sessionPath, sessionPath, sessionPath)
	}
	require.NoError(t, os.WriteFile(script, []byte(body), 0o700))
	return &fakeRefresh{argv: []string{script}, count: count}
}

func (f *fakeRefresh) runs(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(f.count)
	if os.IsNotExist(err) {
		return 0
	}
	require.NoError(t, err)
	return strings.Count(string(data), "run")
}

// grafanaFake accepts only the cookie "sid=new" and records what it received.
type grafanaFake struct {
	*httptest.Server
	mu      sync.Mutex
	cookies []string
	bodies  []string
}

func newGrafanaFake(t *testing.T, onStale http.HandlerFunc) *grafanaFake {
	t.Helper()
	g := &grafanaFake{}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cookie := r.Header.Get("Cookie")
		g.mu.Lock()
		g.cookies = append(g.cookies, cookie)
		g.bodies = append(g.bodies, string(body))
		g.mu.Unlock()
		if cookie != "sid=new" {
			onStale(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(g.Close)
	return g
}

func (g *grafanaFake) seen() (cookies, bodies []string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.cookies...), append([]string(nil), g.bodies...)
}

func unauthorized(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }

func refreshClient(t *testing.T, serverURL, path string, argv []string) *http.Client {
	t.Helper()
	transport, err := BuildTransport(&GrafanaConfig{URL: serverURL, CookieFile: path, CookieRefreshCommand: argv}, nil)
	require.NoError(t, err)
	return &http.Client{Transport: transport}
}

func status(t *testing.T, resp *http.Response, err error) int {
	t.Helper()
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func TestCookieRefreshMissingSession(t *testing.T) {
	g := newGrafanaFake(t, unauthorized)
	path := filepath.Join(t.TempDir(), "session.json")
	fake := newFakeRefresh(t, path, originOf(t, g.URL), "sid=new", false, "0")

	resp, err := refreshClient(t, g.URL, path, fake.argv).Get(g.URL + "/api/health")
	assert.Equal(t, http.StatusOK, status(t, resp, err))

	cookies, _ := g.seen()
	assert.Equal(t, []string{"sid=new"}, cookies, "the stale session is never sent and the new one is used once")
	assert.Equal(t, 1, fake.runs(t))
}

func TestCookieRefreshAfterRejectedSession(t *testing.T) {
	g := newGrafanaFake(t, unauthorized)
	path := filepath.Join(t.TempDir(), "session.json")
	origin := originOf(t, g.URL)
	writeSessionJSON(t, path, sessionJSON(origin, "sid=old", time.Now().Add(time.Hour)), 0o600)
	fake := newFakeRefresh(t, path, origin, "sid=new", false, "0")

	resp, err := refreshClient(t, g.URL, path, fake.argv).Post(g.URL+"/api/dashboards/db", "application/json", bytes.NewReader([]byte("payload")))
	assert.Equal(t, http.StatusOK, status(t, resp, err))

	cookies, bodies := g.seen()
	assert.Equal(t, []string{"sid=old", "sid=new"}, cookies)
	assert.Equal(t, []string{"payload", "payload"}, bodies, "the retry replays the request body")
	assert.Equal(t, 1, fake.runs(t))
}

func TestCookieRefreshAfterRedirectToForeignOrigin(t *testing.T) {
	var foreignRequests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { foreignRequests.Add(1) }))
	defer foreign.Close()
	g := newGrafanaFake(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/login", http.StatusFound)
	})
	path := filepath.Join(t.TempDir(), "session.json")
	origin := originOf(t, g.URL)
	writeSessionJSON(t, path, sessionJSON(origin, "sid=old", time.Now().Add(time.Hour)), 0o600)
	fake := newFakeRefresh(t, path, origin, "sid=new", false, "0")

	resp, err := refreshClient(t, g.URL, path, fake.argv).Get(g.URL + "/api/health")
	assert.Equal(t, http.StatusOK, status(t, resp, err))

	assert.Equal(t, 1, fake.runs(t))
	assert.Zero(t, foreignRequests.Load(), "the sign-in redirect is replaced by the retry, never followed")
}

func TestCookieRefreshIgnoresSameOriginRedirects(t *testing.T) {
	var g *grafanaFake
	g = newGrafanaFake(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/landed" {
			return
		}
		http.Redirect(w, r, g.URL+"/landed", http.StatusFound)
	})
	path := filepath.Join(t.TempDir(), "session.json")
	origin := originOf(t, g.URL)
	writeSessionJSON(t, path, sessionJSON(origin, "sid=old", time.Now().Add(time.Hour)), 0o600)
	fake := newFakeRefresh(t, path, origin, "sid=new", false, "0")

	resp, err := refreshClient(t, g.URL, path, fake.argv).Get(g.URL + "/api/health")
	assert.Equal(t, http.StatusOK, status(t, resp, err))
	assert.Zero(t, fake.runs(t), "a same-origin redirect is not a sign-in")
}

func TestCookieRefreshFailureBacksOff(t *testing.T) {
	g := newGrafanaFake(t, unauthorized)
	path := filepath.Join(t.TempDir(), "session.json")
	fake := newFakeRefresh(t, path, originOf(t, g.URL), "sid="+cookieSecret, true, "0")

	transport, err := newSessionCookieTransport(http.DefaultTransport, path, g.URL, fake.argv)
	require.NoError(t, err)
	now := time.Now()
	transport.refresher.now = func() time.Time { return now }
	client := &http.Client{Transport: transport}

	get := func() error {
		resp, err := client.Get(g.URL + "/api/health")
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	for range 2 {
		err := get()
		require.ErrorContains(t, err, "grafana cookie refresh failed; sign in to Grafana in Chrome once, then retry")
		assert.NotContains(t, err.Error(), cookieSecret)
	}
	assert.Equal(t, 1, fake.runs(t), "the second request inside the back-off window does not run the command")

	now = now.Add(cookieRefreshBackoff + time.Second)
	require.Error(t, get())
	assert.Equal(t, 2, fake.runs(t), "the command runs again once the back-off has passed")
	cookies, _ := g.seen()
	assert.Empty(t, cookies, "no request reaches Grafana without a session")
}

func TestCookieRefreshIsSingleFlight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		initial string
	}{
		{"missing session", ""},
		{"rejected session", "sid=old"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newGrafanaFake(t, unauthorized)
			path := filepath.Join(t.TempDir(), "session.json")
			origin := originOf(t, g.URL)
			if tc.initial != "" {
				writeSessionJSON(t, path, sessionJSON(origin, tc.initial, time.Now().Add(time.Hour)), 0o600)
			}
			fake := newFakeRefresh(t, path, origin, "sid=new", false, "0.3")
			client := refreshClient(t, g.URL, path, fake.argv)

			const n = 8
			codes := make([]int, n)
			var wg sync.WaitGroup
			for i := range n {
				wg.Add(1)
				go func() {
					defer wg.Done()
					resp, err := client.Get(g.URL + "/api/health")
					if err == nil {
						_ = resp.Body.Close()
						codes[i] = resp.StatusCode
					}
				}()
			}
			wg.Wait()

			for _, code := range codes {
				assert.Equal(t, http.StatusOK, code)
			}
			assert.Equal(t, 1, fake.runs(t))
		})
	}
}

func TestCookieRefreshSkipsNonReplayableBody(t *testing.T) {
	g := newGrafanaFake(t, unauthorized)
	path := filepath.Join(t.TempDir(), "session.json")
	origin := originOf(t, g.URL)
	writeSessionJSON(t, path, sessionJSON(origin, "sid=old", time.Now().Add(time.Hour)), 0o600)
	fake := newFakeRefresh(t, path, origin, "sid=new", false, "0")

	// A plain reader gives http.NewRequest no GetBody to rewind with.
	req, err := http.NewRequest(http.MethodPost, g.URL+"/api/dashboards/db", io.NopCloser(strings.NewReader("payload")))
	require.NoError(t, err)
	require.Nil(t, req.GetBody)
	resp, err := refreshClient(t, g.URL, path, fake.argv).Do(req)
	assert.Equal(t, http.StatusUnauthorized, status(t, resp, err), "the original response is returned")

	cookies, _ := g.seen()
	assert.Equal(t, []string{"sid=old"}, cookies)
	assert.Zero(t, fake.runs(t))
}

func TestCookieRefreshWaiterHonorsContext(t *testing.T) {
	g := newGrafanaFake(t, unauthorized)
	path := filepath.Join(t.TempDir(), "session.json")
	fake := newFakeRefresh(t, path, originOf(t, g.URL), "sid=new", false, "1")
	client := refreshClient(t, g.URL, path, fake.argv)

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.URL+"/api/health", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestParseCookieRefreshCommand(t *testing.T) {
	argv, err := ParseCookieRefreshCommand(`["node","/abs/cli.mjs","refresh","https://grafana.example.com"]`)
	require.NoError(t, err)
	assert.Equal(t, []string{"node", "/abs/cli.mjs", "refresh", "https://grafana.example.com"}, argv)

	for _, raw := range []string{`node /abs/cli.mjs`, `["node",`, `[]`, `[""]`, `"node"`, `[1]`} {
		_, err := ParseCookieRefreshCommand(raw)
		require.Error(t, err, raw)
		assert.NotContains(t, err.Error(), "cli.mjs", "the error does not echo the value")
	}
}

func TestCookieRefreshConfigRequiresCookieFile(t *testing.T) {
	_, err := BuildTransport(&GrafanaConfig{URL: "https://grafana.example.com", CookieRefreshCommand: []string{"refresh"}}, nil)
	require.ErrorContains(t, err, "requires a cookie file")

	t.Run("env", func(t *testing.T) {
		t.Setenv(grafanaCookieRefreshCommandEnvVar, `["refresh"]`)
		t.Setenv(grafanaCookieFileEnvVar, "")
		require.ErrorContains(t, ValidateCookieRefreshEnv(), grafanaCookieFileEnvVar)

		t.Setenv(grafanaCookieFileEnvVar, "/run/session.json")
		require.NoError(t, ValidateCookieRefreshEnv())

		t.Setenv(grafanaCookieRefreshCommandEnvVar, `not json`)
		require.Error(t, ValidateCookieRefreshEnv())

		t.Setenv(grafanaCookieRefreshCommandEnvVar, "")
		require.NoError(t, ValidateCookieRefreshEnv())
	})
}

func TestCookieRefreshCommandFromEnv(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	t.Setenv(grafanaCookieFileEnvVar, "/run/session.json")
	t.Setenv(grafanaCookieRefreshCommandEnvVar, `["refresh","https://grafana.example.com"]`)
	want := []string{"refresh", "https://grafana.example.com"}

	assert.Equal(t, want, GrafanaConfigFromContext(ExtractGrafanaInfoFromEnv(context.Background())).CookieRefreshCommand)
	assert.Equal(t, want, GrafanaConfigFromContext(ExtractGrafanaInfoFromHeaders(context.Background(), req)).CookieRefreshCommand)

	t.Run("invalid value leaves refresh off", func(t *testing.T) {
		t.Setenv(grafanaCookieRefreshCommandEnvVar, `{`)
		config := GrafanaConfigFromContext(ExtractGrafanaInfoFromHeaders(context.Background(), req))
		assert.Equal(t, "/run/session.json", config.CookieFile)
		assert.Empty(t, config.CookieRefreshCommand)
	})

	for _, header := range []string{grafanaServiceAccountTokenHeader, grafanaAPIKeyHeader, "Authorization", "Cookie"} {
		t.Run("request credentials clear refresh "+header, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			r.Header.Set(header, "synthetic-credential")
			base := WithGrafanaConfig(t.Context(), GrafanaConfig{CookieFile: "/embedder/session.json", CookieRefreshCommand: []string{"embedder"}})
			config := GrafanaConfigFromContext(ExtractGrafanaInfoFromHeaders(base, r))
			assert.Empty(t, config.CookieFile)
			assert.Empty(t, config.CookieRefreshCommand)
		})
	}

	t.Run("env cookie file replaces the embedder pair", func(t *testing.T) {
		t.Setenv(grafanaCookieRefreshCommandEnvVar, "")
		base := WithGrafanaConfig(t.Context(), GrafanaConfig{CookieFile: "/embedder/session.json", CookieRefreshCommand: []string{"embedder"}})
		config := GrafanaConfigFromContext(ExtractGrafanaInfoFromEnv(base))
		assert.Equal(t, "/run/session.json", config.CookieFile)
		assert.Empty(t, config.CookieRefreshCommand)
	})
}

func TestCookieRefreshSharedPerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	a, err := newSessionCookieTransport(http.DefaultTransport, path, "https://grafana.example.com", []string{"refresh"})
	require.NoError(t, err)
	b, err := newSessionCookieTransport(http.DefaultTransport, path, "https://grafana.example.com", []string{"refresh"})
	require.NoError(t, err)
	other, err := newSessionCookieTransport(http.DefaultTransport, path, "https://other.example.com", []string{"refresh"})
	require.NoError(t, err)
	assert.Same(t, a.refresher, b.refresher, "every transport of a session shares one refresher")
	assert.NotSame(t, a.refresher, other.refresher)
}

func TestSessionCookieFileRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need elevated rights on Windows")
	}
	g := newGrafanaFake(t, unauthorized)
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	writeSessionJSON(t, real, sessionJSON(originOf(t, g.URL), "sid=new", time.Now().Add(time.Hour)), 0o600)
	link := filepath.Join(dir, "session.json")
	require.NoError(t, os.Symlink(real, link))
	fake := newFakeRefresh(t, link, originOf(t, g.URL), "sid=new", false, "0")

	for name, argv := range map[string][]string{"plain": nil, "with refresh": fake.argv} {
		t.Run(name, func(t *testing.T) {
			resp, err := refreshClient(t, g.URL, link, argv).Get(g.URL + "/api/health")
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.ErrorContains(t, err, "must not be a symlink")
		})
	}
	cookies, _ := g.seen()
	assert.Empty(t, cookies)
	assert.Zero(t, fake.runs(t), "a symlink needs the user, not a sign-in")
}
