package smb2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/maestrohub-labs/go-smb2/internal/dfsc"
	"github.com/maestrohub-labs/go-smb2/internal/erref"
	"github.com/maestrohub-labs/go-smb2/internal/smb2"
)

const (
	// maxDFSHops bounds referral chaining (root -> link -> interlink ...)
	// so a misconfigured namespace cannot loop forever. cifs.ko uses the
	// same order of magnitude.
	maxDFSHops = 16
	// minRootTTL floors the cache lifetime of root/interlink entries.
	// Link entries use the server-supplied TimeToLive; roots change
	// rarely, so a short or zero server TTL is floored to avoid hammering
	// the namespace server.
	minRootTTL = 600 * time.Second
)

// dfsResolver follows DFS referrals to a backing (server, share, relPath),
// caching results and reusing one session per backing server. It is
// created lazily on the first DFS-triggering error for a session.
type dfsResolver struct {
	cache *referralCache
	conns *backingConns
	logf  func(format string, args ...any)
	// fetch retrieves one referral for unc from the named server. It is a
	// field so tests can drive the hop loop without a network; the live
	// constructor wires it to the IPC$ IOCTL via the backing-conn map.
	fetch func(ctx context.Context, server, unc string) (*dfsc.ReferralResponse, error)
}

func newDFSResolver(origin *Session) *dfsResolver {
	logf := origin.dialer.DFSLog
	if logf == nil {
		logf = func(string, ...any) {}
	}
	r := &dfsResolver{
		cache: newReferralCache(),
		conns: newBackingConns(origin),
		logf:  logf,
	}
	r.fetch = func(ctx context.Context, server, unc string) (*dfsc.ReferralResponse, error) {
		sess, err := r.conns.sessionFor(ctx, server)
		if err != nil {
			return nil, err
		}
		return sess.dfsGetReferral(ctx, unc)
	}
	return r
}

// close releases backing-server sessions.
func (r *dfsResolver) close() { r.conns.close() }

// resolve follows DFS referrals for unc and returns the backing
// (server, share, relPath). relPath uses backslash separators and has no
// leading separator. A non-DFS path (or one no longer covered) resolves
// to its own split, so resolve is safe to call speculatively.
func (r *dfsResolver) resolve(ctx context.Context, unc string) (server, share, relPath string, err error) {
	unc = normUNC(unc)
	visited := map[string]bool{}

	for range maxDFSHops {
		// Cache fast path: longest-prefix match short-circuits a network
		// round trip.
		if entry, ok := r.cache.longestPrefix(unc); ok {
			unc = entry.target + unc[len(entry.consumedPrefix):]
			if entry.final {
				s, sh, rel := splitUNC(unc)
				return s, sh, rel, nil
			}
			if visited[strings.ToLower(unc)] {
				return "", "", "", fmt.Errorf("dfs: referral loop resolving %q", unc)
			}
			visited[strings.ToLower(unc)] = true
			continue
		}

		srv := serverFromUNC(unc)
		if srv == "" {
			return "", "", "", fmt.Errorf("dfs: cannot extract server from %q", unc)
		}

		resp, rerr := r.fetch(ctx, srv, unc)
		if rerr != nil {
			if isNotDFSReferral(rerr) {
				// The path is not (or no longer) DFS-covered: use it
				// as-is. This terminates chains whose final hop lands on
				// a plain file server.
				s, sh, rel := splitUNC(unc)
				return s, sh, rel, nil
			}
			return "", "", "", fmt.Errorf("dfs: referral for %q: %w", unc, rerr)
		}

		pick := bestTarget(resp)
		if pick == nil || resp.PathConsumed == 0 {
			// No usable target — treat as not covered.
			s, sh, rel := splitUNC(unc)
			return s, sh, rel, nil
		}

		final := resp.HeaderFlags&dfsc.HeaderFlagStorageServers != 0
		ttl := pick.TTL
		if !final && ttl < minRootTTL {
			ttl = minRootTTL
		}
		if ttl <= 0 {
			ttl = minRootTTL
		}

		consumed := utf16Prefix(unc, resp.PathConsumed)
		r.cache.put(consumed, pick.TargetUNC, ttl, final)

		unc = pick.TargetUNC + utf16Suffix(unc, resp.PathConsumed)
		if final {
			s, sh, rel := splitUNC(unc)
			return s, sh, rel, nil
		}

		if visited[strings.ToLower(unc)] {
			return "", "", "", fmt.Errorf("dfs: referral loop resolving %q", unc)
		}
		visited[strings.ToLower(unc)] = true
	}

	return "", "", "", fmt.Errorf("dfs: exceeded %d referral hops resolving %q", maxDFSHops, unc)
}

// bestTarget picks the first referral entry that carries a target UNC.
// MS-DFSC lists targets in server preference order, so the first active
// entry is the right default; richer policies (failback, site costing)
// can be layered on later.
func bestTarget(resp *dfsc.ReferralResponse) *dfsc.Referral {
	for i := range resp.Referrals {
		if resp.Referrals[i].TargetUNC != "" {
			return &resp.Referrals[i]
		}
	}
	return nil
}

// isNotDFSReferral reports whether err means "this path is not served by
// DFS" — the benign signal that resolution has reached a plain file
// server (or that the path was never DFS). It is treated as "use the path
// as-is", not a failure.
func isNotDFSReferral(err error) bool {
	var re *ResponseError
	if !errors.As(err, &re) {
		return false
	}
	switch erref.NtStatus(re.Code) {
	case erref.STATUS_NOT_FOUND,
		erref.STATUS_OBJECT_NAME_NOT_FOUND,
		erref.STATUS_OBJECT_PATH_NOT_FOUND,
		erref.STATUS_NOT_SUPPORTED,
		erref.STATUS_INVALID_DEVICE_REQUEST,
		erref.STATUS_NO_SUCH_DEVICE,
		erref.STATUS_FS_DRIVER_REQUIRED:
		return true
	}
	return false
}

// supportsDFS reports whether the session's server advertised the DFS
// global capability during negotiation.
func (c *Session) supportsDFS() bool {
	return c.s.capabilities&smb2.SMB2_GLOBAL_CAP_DFS != 0
}

// --- UNC helpers --------------------------------------------------------

// normUNC normalizes any UNC form to a single-leading-backslash path
// (`\server\share\...`), the form MS-DFSC RequestFileName uses and that
// PathConsumed is measured against. Forward slashes become backslashes.
func normUNC(unc string) string {
	unc = strings.ReplaceAll(unc, "/", `\`)
	unc = strings.TrimLeft(unc, `\`)
	return `\` + unc
}

// serverFromUNC returns the server component of `\server\share\...`.
func serverFromUNC(unc string) string {
	parts := strings.Split(strings.TrimLeft(normUNC(unc), `\`), `\`)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

// splitUNC splits `\server\share\rel\path` into its server, share, and
// share-relative remainder (backslash-separated, no leading separator).
func splitUNC(unc string) (server, share, relPath string) {
	parts := strings.Split(strings.TrimLeft(normUNC(unc), `\`), `\`)
	switch len(parts) {
	case 0:
		return "", "", ""
	case 1:
		return parts[0], "", ""
	case 2:
		return parts[0], parts[1], ""
	default:
		return parts[0], parts[1], strings.Join(parts[2:], `\`)
	}
}

// utf16Prefix returns the prefix of s covered by pathConsumedBytes bytes
// of UTF-16 (so /2 = code units). Counting in UTF-16 units matches how
// the server measured PathConsumed and avoids the classic byte-vs-char
// off-by-two bug on non-ASCII paths.
func utf16Prefix(s string, pathConsumedBytes uint16) string {
	units := utf16.Encode([]rune(s))
	n := min(int(pathConsumedBytes)/2, len(units))
	return string(utf16.Decode(units[:n]))
}

// utf16Suffix returns the remainder of s after pathConsumedBytes bytes of
// UTF-16, the part of the path not covered by the referral.
func utf16Suffix(s string, pathConsumedBytes uint16) string {
	units := utf16.Encode([]rune(s))
	n := min(int(pathConsumedBytes)/2, len(units))
	return string(utf16.Decode(units[n:]))
}
