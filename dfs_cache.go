package smb2

import (
	"strings"
	"sync"
	"time"
)

// referralEntry is one cached DFS mapping: a consumed namespace prefix
// that resolves to a target UNC prefix, valid until deadline.
type referralEntry struct {
	// consumedPrefix is the namespace-side prefix this entry replaces,
	// in original case (its byte length is used to strip it from a query
	// UNC). DFS names are effectively ASCII, so byte length and the
	// case-folded match length agree.
	consumedPrefix string
	// target is the backing UNC prefix that consumedPrefix maps to, e.g.
	// `\backing\share`.
	target string
	// deadline is when this entry expires (now + TTL at insertion).
	deadline time.Time
	// final reports whether target is a storage server (terminal). When
	// false the target is itself a DFS server whose path needs further
	// resolution (a root / interlink referral).
	final bool
}

// referralCache is a TTL cache of DFS referrals keyed by the lowercased
// consumed-prefix UNC (DFS is case-insensitive). Lookup is a
// longest-prefix match on a path-component boundary; expired entries are
// evicted lazily on access.
type referralCache struct {
	mu sync.Mutex
	m  map[string]referralEntry // key: strings.ToLower(consumedPrefix)
	// now is the clock, overridable in tests.
	now func() time.Time
}

func newReferralCache() *referralCache {
	return &referralCache{m: make(map[string]referralEntry), now: time.Now}
}

// put inserts or replaces the mapping for consumedPrefix.
func (c *referralCache) put(consumedPrefix, target string, ttl time.Duration, final bool) {
	if consumedPrefix == "" || target == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[strings.ToLower(consumedPrefix)] = referralEntry{
		consumedPrefix: consumedPrefix,
		target:         target,
		deadline:       c.now().Add(ttl),
		final:          final,
	}
}

// longestPrefix returns the cached entry whose lowercased consumedPrefix
// is the longest path-component-boundary prefix of unc and has not
// expired. Expired entries encountered during the scan are evicted.
func (c *referralCache) longestPrefix(unc string) (referralEntry, bool) {
	lower := strings.ToLower(unc)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	var best referralEntry
	var bestLen = -1
	for key, entry := range c.m {
		if !entry.deadline.After(now) {
			delete(c.m, key) // evict expired
			continue
		}
		if !boundaryPrefix(lower, key) {
			continue
		}
		if len(key) > bestLen {
			best, bestLen = entry, len(key)
		}
	}
	if bestLen < 0 {
		return referralEntry{}, false
	}
	return best, true
}

// boundaryPrefix reports whether prefix is a prefix of s that ends on a
// path-component boundary — i.e. s equals prefix, or the character of s
// right after prefix is a path separator. This stops `\srv\share` from
// matching a query for `\srv\share2`.
func boundaryPrefix(s, prefix string) bool {
	if !strings.HasPrefix(s, prefix) {
		return false
	}
	return len(s) == len(prefix) || s[len(prefix)] == '\\'
}
