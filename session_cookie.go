package mcpgrafana

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// sessionExpiryGrace matches SESSION_EXPIRY_GRACE_SECONDS in the Loglens
	// session-file contract: a cookie that expires sooner is treated as expired.
	sessionExpiryGrace = 60 * time.Second
	maxSessionFileSize = 1 << 20
)

// sessionFile is the origin-keyed file written by the Loglens broker. Origins
// use the browser URL.origin form, e.g. "https://grafana.example.com".
type sessionFile struct {
	Sessions map[string]sessionCookie `json:"sessions"`
}

type sessionCookie struct {
	// Value is a complete Cookie request header value, e.g. "a=1; b=2".
	Value string `json:"value"`
	// Expires, UpdatedAt and CapturedAt are Unix seconds.
	Expires    int64 `json:"expires"`
	UpdatedAt  int64 `json:"updatedAt"`
	CapturedAt int64 `json:"capturedAt,omitzero"`
}

// sessionCookieTransport replaces the Cookie header of every request with the
// session stored in a file for the configured Grafana origin. The file is read
// on each request so a rotated session is used without restarting. Errors
// never contain file contents, and a request is never sent without the cookie.
type sessionCookieTransport struct {
	next    http.RoundTripper
	path    string
	baseURL *url.URL
	origin  string
}

func newSessionCookieTransport(next http.RoundTripper, path, grafanaURL string) (*sessionCookieTransport, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("grafana cookie file must be an absolute path")
	}
	if grafanaURL == "" {
		grafanaURL = defaultGrafanaURL
	}
	baseURL, err := url.Parse(normalizeGrafanaURL(grafanaURL))
	if err != nil {
		return nil, errors.New("grafana cookie file requires a valid Grafana URL")
	}
	origin, ok := sessionOrigin(baseURL)
	if !ok {
		return nil, errors.New("grafana cookie file requires an http(s) Grafana URL")
	}
	return &sessionCookieTransport{next: next, path: path, baseURL: baseURL, origin: origin}, nil
}

// sessionOrigin formats u like the browser's URL.origin, which is how the
// broker keys the session file.
func sessionOrigin(u *url.URL) (string, bool) {
	scheme, host, port, ok := httpOriginParts(u)
	if !ok {
		return "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return scheme + "://" + host, true
	}
	return scheme + "://" + host + ":" + port, true
}

func (t *sessionCookieTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cookie, err := t.cookieFor(req.URL)
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	cloned := req.Clone(req.Context())
	cloned.Header.Set("Cookie", cookie)
	return t.next.RoundTrip(cloned)
}

func (t *sessionCookieTransport) cookieFor(target *url.URL) (string, error) {
	if !sameHTTPOrigin(target, t.baseURL) {
		return "", fmt.Errorf("grafana cookie file: refusing to send session for %s to %s", t.origin, redirectOriginForError(target))
	}
	session, err := t.readSession()
	if err != nil {
		return "", err
	}
	if session.Expires <= time.Now().Add(sessionExpiryGrace).Unix() {
		return "", fmt.Errorf("grafana cookie file: session for %s is expired or expires within %s; sign in again in the browser and let the extension sync", t.origin, sessionExpiryGrace)
	}
	if _, err := http.ParseCookie(session.Value); err != nil {
		return "", fmt.Errorf("grafana cookie file: session for %s is not a valid Cookie header value", t.origin)
	}
	return session.Value, nil
}

func (t *sessionCookieTransport) readSession() (sessionCookie, error) {
	f, err := os.Open(t.path)
	if err != nil {
		return sessionCookie{}, fmt.Errorf("grafana cookie file: %w", err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return sessionCookie{}, fmt.Errorf("grafana cookie file: %s is not a readable regular file", t.path)
	}
	// Windows has no POSIX permission bits, so only enforce this elsewhere.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return sessionCookie{}, fmt.Errorf("grafana cookie file: %s must not be accessible by group or others (chmod 600)", t.path)
	}

	// Decode errors are replaced with a fixed message because they can quote file content.
	dec := json.NewDecoder(io.LimitReader(f, maxSessionFileSize))
	dec.DisallowUnknownFields()
	var file sessionFile
	if dec.Decode(&file) != nil || dec.Decode(&struct{}{}) != io.EOF {
		return sessionCookie{}, fmt.Errorf("grafana cookie file: %s is not a valid origin-keyed session file", t.path)
	}
	session, ok := file.Sessions[t.origin]
	if !ok {
		return sessionCookie{}, fmt.Errorf("grafana cookie file: %s has no session for %s", t.path, t.origin)
	}
	return session, nil
}
