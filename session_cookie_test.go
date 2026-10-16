package mcpgrafana

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cookieSecret marks every credential-like value written to the fixture files,
// so a leak into an error message is detectable.
const cookieSecret = "SYNTHETIC-SECRET"

func originOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)
	return u.Scheme + "://" + u.Host
}

// writeSessionJSON replaces the session file atomically, like the broker does.
func writeSessionJSON(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(content), mode))
	require.NoError(t, os.Chmod(tmp, mode))
	require.NoError(t, os.Rename(tmp, path))
}

func sessionJSON(origin, cookie string, expires time.Time) string {
	return fmt.Sprintf(`{"sessions":{%q:{"value":%q,"expires":%d,"updatedAt":1,"capturedAt":1}}}`, origin, cookie, expires.Unix())
}

func TestBuildTransportCookieFileSendsCurrentSession(t *testing.T) {
	var got atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Values("Cookie"))
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "session.json")
	origin := originOf(t, server.URL)
	writeSessionJSON(t, path, sessionJSON(origin, "sid=one; csrf=a", time.Now().Add(time.Hour)), 0o600)

	transport, err := BuildTransport(&GrafanaConfig{
		URL:          server.URL,
		CookieFile:   path,
		ExtraHeaders: map[string]string{"Cookie": "sid=stale"},
	}, nil)
	require.NoError(t, err)
	httpClient := &http.Client{Transport: transport}

	do := func(req *http.Request) {
		t.Helper()
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/health", nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "caller=1")
	do(req)
	assert.Equal(t, []string{"sid=one; csrf=a"}, got.Load(), "file cookie replaces forwarded and extra Cookie headers")
	assert.Equal(t, []string{"caller=1"}, req.Header.Values("Cookie"), "caller's request is not mutated")

	writeSessionJSON(t, path, sessionJSON(origin, "sid=two", time.Now().Add(time.Hour)), 0o600)
	req, err = http.NewRequest(http.MethodGet, server.URL+"/api/health", nil)
	require.NoError(t, err)
	do(req)
	assert.Equal(t, []string{"sid=two"}, got.Load(), "rotated file is used by the same client")
}

func TestBuildTransportCookieFileRejectsUnusableSession(t *testing.T) {
	good := func(origin string) string { return sessionJSON(origin, "sid="+cookieSecret, time.Now().Add(time.Hour)) }
	for _, tc := range []struct {
		name    string
		content func(origin string) string
		mode    os.FileMode
		want    string
	}{
		{"missing file", nil, 0o600, "no such file"},
		{"malformed JSON", func(string) string { return `{"sessions": ` + cookieSecret }, 0o600, "not a valid origin-keyed session file"},
		{"trailing data", func(o string) string { return good(o) + cookieSecret }, 0o600, "not a valid origin-keyed session file"},
		{"legacy flat file", func(string) string {
			return fmt.Sprintf(`{"value":"sid=%s","expires":%d,"updatedAt":1}`, cookieSecret, time.Now().Add(time.Hour).Unix())
		}, 0o600, "not a valid origin-keyed session file"},
		{"unknown field", func(o string) string {
			return strings.Replace(good(o), `"updatedAt"`, `"`+cookieSecret+`":1,"updatedAt"`, 1)
		}, 0o600, "not a valid origin-keyed session file"},
		{"other origin only", func(string) string { return good("https://other.example.com") }, 0o600, "has no session for"},
		{"expired", func(o string) string { return sessionJSON(o, "sid="+cookieSecret, time.Now().Add(-time.Minute)) }, 0o600, "expired"},
		{"inside expiry grace", func(o string) string { return sessionJSON(o, "sid="+cookieSecret, time.Now().Add(30*time.Second)) }, 0o600, "expired"},
		{"empty cookie header", func(o string) string {
			return sessionJSON(o, "", time.Now().Add(time.Hour))
		}, 0o600, "not a valid Cookie header"},
		{"invalid cookie header", func(o string) string {
			return sessionJSON(o, "sid="+cookieSecret+"\r\nX-Injected: 1", time.Now().Add(time.Hour))
		}, 0o600, "not a valid Cookie header"},
		{"group readable", good, 0o640, "must not be accessible by group or others"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.mode&0o077 != 0 && runtime.GOOS == "windows" {
				t.Skip("Windows has no POSIX permission bits")
			}
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			defer server.Close()

			path := filepath.Join(t.TempDir(), "session.json")
			if tc.content != nil {
				writeSessionJSON(t, path, tc.content(originOf(t, server.URL)), tc.mode)
			}
			transport, err := BuildTransport(&GrafanaConfig{URL: server.URL, CookieFile: path}, nil)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodGet, server.URL+"/api/health", nil)
			require.NoError(t, err)
			resp, err := (&http.Client{Transport: transport}).Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
			assert.NotContains(t, err.Error(), cookieSecret)
			assert.Zero(t, requests.Load(), "no request may reach Grafana without a valid session")
		})
	}

	t.Run("relative path", func(t *testing.T) {
		_, err := BuildTransport(&GrafanaConfig{URL: "https://grafana.example.com", CookieFile: "session.json"}, nil)
		require.ErrorContains(t, err, "absolute path")
	})
}

func TestBuildTransportCookieFileOriginBinding(t *testing.T) {
	var foreignRequests, grafanaRequests atomic.Int32
	var foreignCookie atomic.Value
	foreign := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		foreignRequests.Add(1)
		foreignCookie.Store(r.Header.Get("Cookie"))
	}))
	defer foreign.Close()

	var grafana *httptest.Server
	grafana = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		grafanaRequests.Add(1)
		assert.Equal(t, "sid=grafana", r.Header.Get("Cookie"))
		switch r.URL.Path {
		case "/same-origin":
			http.Redirect(w, r, grafana.URL+"/landed", http.StatusFound)
		case "/cross-origin":
			http.Redirect(w, r, foreign.URL+"/capture", http.StatusFound)
		}
	}))
	defer grafana.Close()

	// The shared file holds a session for the foreign origin as well, so the
	// provider could leak it if it selected sessions by request origin.
	path := filepath.Join(t.TempDir(), "session.json")
	exp := time.Now().Add(time.Hour).Unix()
	writeSessionJSON(t, path, fmt.Sprintf(
		`{"sessions":{%q:{"value":"sid=grafana","expires":%d,"updatedAt":1},%q:{"value":"sid=foreign","expires":%d,"updatedAt":1}}}`,
		originOf(t, grafana.URL), exp, originOf(t, foreign.URL), exp), 0o600)

	for _, allowCrossOrigin := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow cross-origin redirects %t", allowCrossOrigin), func(t *testing.T) {
			foreignRequests.Store(0)
			transport, err := BuildTransport(&GrafanaConfig{URL: grafana.URL, CookieFile: path, AllowCrossOriginRedirects: allowCrossOrigin}, nil)
			require.NoError(t, err)
			httpClient := &http.Client{Transport: transport}

			resp, err := httpClient.Get(foreign.URL + "/direct")
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.ErrorContains(t, err, "refusing to send session")

			resp, err = httpClient.Get(grafana.URL + "/cross-origin")
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			assert.Zero(t, foreignRequests.Load(), "foreign origin received a request, cookie %v", foreignCookie.Load())

			before := grafanaRequests.Load()
			resp, err = httpClient.Get(grafana.URL + "/same-origin")
			require.NoError(t, err)
			_ = resp.Body.Close()
			assert.Equal(t, before+2, grafanaRequests.Load(), "same-origin redirect is followed with the session")
		})
	}
}

func TestBuildTransportWithoutAuthSkipsCookieFile(t *testing.T) {
	var got atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Cookie"))
	}))
	defer server.Close()

	transport, err := BuildTransport(&GrafanaConfig{
		URL:        server.URL,
		CookieFile: filepath.Join(t.TempDir(), "missing.json"),
	}, nil, WithoutAuth())
	require.NoError(t, err)

	resp, err := (&http.Client{Transport: transport}).Get(server.URL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Empty(t, got.Load())
}
