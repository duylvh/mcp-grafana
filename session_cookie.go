package mcpgrafana

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// refresher is nil unless a refresh command is configured.
	refresher *cookieRefresher
}

// staleSessionError marks a missing or expired session, the cases a refresh
// command can repair, apart from a malformed file or a refused origin.
type staleSessionError struct{ err error }

func (e *staleSessionError) Error() string { return e.err.Error() }
func (e *staleSessionError) Unwrap() error { return e.err }

func newSessionCookieTransport(next http.RoundTripper, path, grafanaURL string, refreshCommand []string) (*sessionCookieTransport, error) {
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
	t := &sessionCookieTransport{next: next, path: path, baseURL: baseURL, origin: origin}
	if len(refreshCommand) > 0 {
		t.refresher = cookieRefresherFor(path, refreshCommand)
	}
	return t, nil
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

// RoundTrip sends req with the session cookie. With a refresh command, a
// missing or expired session, a 401, or a redirect away from Grafana (the
// sign-in page of an SSO proxy) renews the session and retries once.
func (t *sessionCookieTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.refresher == nil {
		return t.send(req)
	}
	generation := t.refresher.Generation()
	resp, err := t.send(req)
	if !t.sessionRejected(req, resp, err) || !replayable(req) {
		return resp, err
	}
	if resp != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
	}
	if err := t.refresher.Refresh(req.Context(), generation); err != nil {
		return nil, err
	}
	retry, err := rewound(req)
	if err != nil {
		return nil, err
	}
	return t.send(retry)
}

func (t *sessionCookieTransport) send(req *http.Request) (*http.Response, error) {
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

func (t *sessionCookieTransport) sessionRejected(req *http.Request, resp *http.Response, err error) bool {
	if err != nil {
		var stale *staleSessionError
		return errors.As(err, &stale)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return true
	}
	if resp.StatusCode < 300 || resp.StatusCode > 399 {
		return false
	}
	location, err := req.URL.Parse(resp.Header.Get("Location"))
	return err == nil && !sameHTTPOrigin(location, t.baseURL)
}

func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

// rewound returns req with a fresh body, since sending consumed the original.
func rewound(req *http.Request) (*http.Request, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	retry := req.Clone(req.Context())
	retry.Body = body
	return retry, nil
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
		return "", &staleSessionError{fmt.Errorf("grafana cookie file: session for %s is expired or expires within %s; sign in to Grafana in the browser again", t.origin, sessionExpiryGrace)}
	}
	if _, err := http.ParseCookie(session.Value); err != nil {
		return "", fmt.Errorf("grafana cookie file: session for %s is not a valid Cookie header value", t.origin)
	}
	return session.Value, nil
}

func (t *sessionCookieTransport) readSession() (sessionCookie, error) {
	f, err := os.Open(t.path)
	if err != nil {
		err = fmt.Errorf("grafana cookie file: %w", err)
		if errors.Is(err, fs.ErrNotExist) {
			err = &staleSessionError{err}
		}
		return sessionCookie{}, err
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
		return sessionCookie{}, &staleSessionError{fmt.Errorf("grafana cookie file: %s has no session for %s", t.path, t.origin)}
	}
	return session, nil
}
