package mcpgrafana

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	cookieRefreshTimeout = 90 * time.Second
	cookieRefreshBackoff = 60 * time.Second

	errCookieRefreshFailed = "grafana cookie refresh failed; sign in to Grafana in Chrome once, then retry"
)

// ParseCookieRefreshCommand parses the value of GRAFANA_COOKIE_REFRESH_COMMAND:
// a JSON array holding the program and its arguments. It is run without a
// shell. Errors never quote the value.
func ParseCookieRefreshCommand(raw string) ([]string, error) {
	var argv []string
	if err := json.Unmarshal([]byte(raw), &argv); err != nil {
		return nil, fmt.Errorf("%s must be a JSON array of strings", grafanaCookieRefreshCommandEnvVar)
	}
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("%s must name a program", grafanaCookieRefreshCommandEnvVar)
	}
	return argv, nil
}

// ValidateCookieRefreshEnv reports a misconfigured
// GRAFANA_COOKIE_REFRESH_COMMAND so the server can refuse to start.
func ValidateCookieRefreshEnv() error {
	raw := getEnv(grafanaCookieRefreshCommandEnvVar)
	if raw == "" {
		return nil
	}
	if _, err := ParseCookieRefreshCommand(raw); err != nil {
		return err
	}
	if getEnv(grafanaCookieFileEnvVar) == "" {
		return fmt.Errorf("%s requires %s", grafanaCookieRefreshCommandEnvVar, grafanaCookieFileEnvVar)
	}
	return nil
}

// applyCookieEnv lets GRAFANA_COOKIE_FILE override the configured cookie file.
// The refresh command belongs to the file it renews, so it is replaced with it.
func applyCookieEnv(config *GrafanaConfig) {
	cookieFile := getEnv(grafanaCookieFileEnvVar)
	if cookieFile == "" {
		return
	}
	config.CookieFile = cookieFile
	config.CookieRefreshCommand = nil
	raw := getEnv(grafanaCookieRefreshCommandEnvVar)
	if raw == "" {
		return
	}
	argv, err := ParseCookieRefreshCommand(raw)
	if err != nil {
		config.LoggerOrDefault().Error("ignoring cookie refresh command", "error", err)
		return
	}
	config.CookieRefreshCommand = argv
}

// cookieRefresher runs the refresh command for every transport that shares a
// session file. One run is in flight at a time, requests that were already
// waiting on a stale session share its result, and a failure pauses new runs.
type cookieRefresher struct {
	argv []string
	now  func() time.Time

	mu          sync.Mutex
	generation  uint64
	inflight    chan struct{}
	lastErr     error
	lastFailure time.Time
}

var cookieRefreshers sync.Map

func cookieRefresherFor(path string, argv []string) *cookieRefresher {
	key := path + "\x00" + strings.Join(argv, "\x00")
	r, _ := cookieRefreshers.LoadOrStore(key, &cookieRefresher{argv: argv, now: time.Now})
	return r.(*cookieRefresher)
}

// Generation identifies how many runs have finished. A request reads it before
// it first uses the session, so a run that finished meanwhile is not repeated.
func (r *cookieRefresher) Generation() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.generation
}

// Refresh returns nil when the session file was renewed since generation was
// read or by a run it joins or starts.
func (r *cookieRefresher) Refresh(ctx context.Context, generation uint64) error {
	for {
		r.mu.Lock()
		if r.generation != generation {
			err := r.lastErr
			r.mu.Unlock()
			return err
		}
		if wait := r.inflight; wait != nil {
			r.mu.Unlock()
			select {
			case <-wait:
				continue
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if !r.lastFailure.IsZero() && r.now().Sub(r.lastFailure) < cookieRefreshBackoff {
			r.mu.Unlock()
			return errors.New(errCookieRefreshFailed)
		}
		done := make(chan struct{})
		r.inflight = done
		r.mu.Unlock()

		err := r.run()

		r.mu.Lock()
		r.generation++
		r.lastErr = err
		if err != nil {
			r.lastFailure = r.now()
		}
		r.inflight = nil
		r.mu.Unlock()
		close(done)
		return err
	}
}

// run is detached from the caller's context because other requests wait on it.
func (r *cookieRefresher) run() error {
	ctx, cancel := context.WithTimeout(context.Background(), cookieRefreshTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.argv[0], r.argv[1:]...)
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		slog.Warn("grafana cookie refresh command failed", "error", err)
		return errors.New(errCookieRefreshFailed)
	}
	return nil
}
