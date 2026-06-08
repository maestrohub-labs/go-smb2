package dfsc

import "time"

// ReferralEntry flags ([MS-DFSC] 2.2.5.3 / 2.2.5.4, ReferralEntryFlags).
const (
	// EntryFlagNameListReferral selects the domain/DC NameList layout of
	// a v3/v4 entry instead of the normal target layout.
	EntryFlagNameListReferral = 0x0002
)

// ServerType values ([MS-DFSC] 2.2.5.x, ServerType field).
const (
	// ServerTypeLink marks a non-root (link / leaf storage) target.
	ServerTypeLink = 0x0000
	// ServerTypeRoot marks a root (namespace) referral.
	ServerTypeRoot = 0x0001
)

// Referral is one decoded DFS referral entry, normalized across versions
// 1-4 ([MS-DFSC] 2.2.5.1-2.2.5.4). Version-specific framing is hidden by
// the decoder; callers see a uniform shape.
type Referral struct {
	// Version is the entry's VersionNumber (1-4).
	Version uint16
	// ServerType is the raw ServerType field (ServerTypeRoot /
	// ServerTypeLink).
	ServerType uint16
	// EntryFlags is the raw ReferralEntryFlags field.
	EntryFlags uint16
	// TTL is the TimeToLive in seconds, as a Duration. Zero for v1
	// (which carries no TTL).
	TTL time.Duration
	// Path is the DFSPath this entry maps — the namespace-side path the
	// referral covers (v1: the inline ShareName).
	Path string
	// AltPath is the DFSAlternatePath (an 8.3 alias); usually empty.
	AltPath string
	// TargetUNC is the NetworkAddress: the backing target, e.g.
	// `\backing\share` or `\backing\share\dir`. For a NameList referral
	// it is the first expanded (DC) name. For v1 it equals the inline
	// ShareName.
	TargetUNC string
}

// IsNameList reports whether the entry used the NameListReferral layout.
func (r Referral) IsNameList() bool {
	return r.EntryFlags&EntryFlagNameListReferral != 0
}

// IsRootTarget reports whether ServerType marks this as a root
// (namespace) referral rather than a link/leaf storage target.
func (r Referral) IsRootTarget() bool {
	return r.ServerType == ServerTypeRoot
}
