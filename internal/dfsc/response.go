package dfsc

import (
	"fmt"
	"time"
	"unicode/utf16"
)

// ReferralHeaderFlags bits ([MS-DFSC] 2.2.4, ReferralHeaderFlags).
const (
	HeaderFlagReferralServers = 0x00000001 // R: targets hold further referrals
	HeaderFlagStorageServers  = 0x00000002 // S: targets are storage servers
	HeaderFlagTargetFailback  = 0x00000004 // T: client may fail back
)

// ReferralResponse is RESP_GET_DFS_REFERRAL ([MS-DFSC] 2.2.4):
//
//	PathConsumed        (2 bytes)
//	NumberOfReferrals   (2 bytes)
//	ReferralHeaderFlags (4 bytes)
//	ReferralEntries     (NumberOfReferrals entries, version 1-4)
type ReferralResponse struct {
	// PathConsumed is the number of BYTES of the request's
	// RequestFileName (UTF-16, so /2 = characters) covered by these
	// referrals. It is the authoritative split between the consumed
	// namespace prefix and the remaining path; callers must use it
	// rather than re-deriving the split by string matching.
	PathConsumed uint16
	// HeaderFlags is the raw ReferralHeaderFlags field.
	HeaderFlags uint32
	// Referrals are the decoded entries, in server order.
	Referrals []Referral
}

// referralHeaderSize is the fixed RESP_GET_DFS_REFERRAL header before
// the first entry.
const referralHeaderSize = 8

// DecodeReferralResponse parses the IOCTL output buffer into a
// ReferralResponse. It tolerates trailing bytes after the last entry but
// rejects truncated or malformed entries.
func DecodeReferralResponse(b []byte) (*ReferralResponse, error) {
	if len(b) < referralHeaderSize {
		return nil, fmt.Errorf("dfsc: response too short: %d bytes", len(b))
	}

	resp := &ReferralResponse{
		PathConsumed: le.Uint16(b[0:2]),
		HeaderFlags:  le.Uint32(b[4:8]),
	}
	num := int(le.Uint16(b[2:4]))

	off := referralHeaderSize
	for i := range num {
		ref, size, err := decodeEntry(b, off)
		if err != nil {
			return nil, fmt.Errorf("dfsc: referral entry %d: %w", i, err)
		}
		resp.Referrals = append(resp.Referrals, ref)
		off += size
	}

	return resp, nil
}

// decodeEntry parses one referral entry starting at b[start:] and returns
// the entry plus its byte size (so the caller can advance). String
// offsets in versions 2-4 are relative to the start of the entry.
func decodeEntry(b []byte, start int) (Referral, int, error) {
	if start+8 > len(b) {
		return Referral{}, 0, fmt.Errorf("truncated header at offset %d", start)
	}
	entry := b[start:]

	version := le.Uint16(entry[0:2])
	size := int(le.Uint16(entry[2:4]))
	if size < 8 {
		return Referral{}, 0, fmt.Errorf("implausible entry size %d", size)
	}
	if start+size > len(b) {
		return Referral{}, 0, fmt.Errorf("entry size %d overruns buffer (start %d, len %d)", size, start, len(b))
	}

	r := Referral{
		Version:    version,
		ServerType: le.Uint16(entry[4:6]),
		EntryFlags: le.Uint16(entry[6:8]),
	}

	switch version {
	case 1:
		// [MS-DFSC] 2.2.5.1: VersionNumber, Size, ServerType,
		// ReferralEntryFlags, then an inline null-terminated UTF-16
		// ShareName (no offsets, no TTL).
		r.TargetUNC = utf16zRel(b, start, 8)
		r.Path = r.TargetUNC
	case 2:
		// [MS-DFSC] 2.2.5.2: + Proximity(4), TimeToLive(4),
		// DFSPathOffset(2), DFSAlternatePathOffset(2),
		// NetworkAddressOffset(2). Offsets relative to entry start.
		if size < 22 {
			return Referral{}, 0, fmt.Errorf("v2 entry too small: %d", size)
		}
		r.TTL = time.Duration(le.Uint32(entry[12:16])) * time.Second
		r.Path = utf16zRel(b, start, le.Uint16(entry[16:18]))
		r.AltPath = utf16zRel(b, start, le.Uint16(entry[18:20]))
		r.TargetUNC = utf16zRel(b, start, le.Uint16(entry[20:22]))
	case 3, 4:
		// [MS-DFSC] 2.2.5.3 (v3) / 2.2.5.4 (v4). VersionNumber, Size,
		// ServerType, ReferralEntryFlags, TimeToLive(4), then either the
		// normal target layout or the NameList layout, selected by the
		// NameListReferral flag.
		if size < 12 {
			return Referral{}, 0, fmt.Errorf("v%d entry too small: %d", version, size)
		}
		r.TTL = time.Duration(le.Uint32(entry[8:12])) * time.Second
		if r.IsNameList() {
			// SpecialNameOffset(2), NumberOfExpandedNames(2),
			// ExpandedNameOffset(2). The expanded names are a packed run
			// of null-terminated UTF-16 strings; we surface the first.
			if size < 18 {
				return Referral{}, 0, fmt.Errorf("v%d namelist entry too small: %d", version, size)
			}
			r.Path = utf16zRel(b, start, le.Uint16(entry[12:14]))
			r.TargetUNC = utf16zRel(b, start, le.Uint16(entry[16:18]))
		} else {
			// DFSPathOffset(2), DFSAlternatePathOffset(2),
			// NetworkAddressOffset(2), ServiceSiteGuid(16, ignored).
			if size < 18 {
				return Referral{}, 0, fmt.Errorf("v%d target entry too small: %d", version, size)
			}
			r.Path = utf16zRel(b, start, le.Uint16(entry[12:14]))
			r.AltPath = utf16zRel(b, start, le.Uint16(entry[14:16]))
			r.TargetUNC = utf16zRel(b, start, le.Uint16(entry[16:18]))
		}
	default:
		return Referral{}, 0, fmt.Errorf("unsupported referral version %d", version)
	}

	return r, size, nil
}

// utf16zRel reads a null-terminated UTF-16LE string located at
// (entryStart + off). off is relative to the entry start, as specified
// by MS-DFSC. An off of 0 means "absent" and yields "".
//
// The read is bounded by the end of the whole referral buffer, NOT by the
// entry's fixed Size: in v2-v4 entries the DFSPath / NetworkAddress strings
// do not live inside the fixed entry — they sit in a shared string pool that
// follows all the fixed entries, so their offsets routinely point well past
// (entryStart + Size). Clamping to the entry size (the previous behavior) made
// every v3/v4 NetworkAddress decode to "", which silently broke referral
// following on real Windows DFS (the resolver saw an empty TargetUNC, found no
// usable target, and treated the link as not covered). The null terminator
// delimits the string; len(b) is the safety bound against a malformed offset.
func utf16zRel(b []byte, entryStart int, off uint16) string {
	if off == 0 {
		return ""
	}
	start := entryStart + int(off)
	end := len(b)
	if start < 0 || start >= end {
		return ""
	}

	var u []uint16
	for p := start; p+2 <= end; p += 2 {
		v := le.Uint16(b[p : p+2])
		if v == 0 {
			break
		}
		u = append(u, v)
	}
	return string(utf16.Decode(u))
}
