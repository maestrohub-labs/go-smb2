// Package dfsc implements the MS-DFSC referral request/response wire
// format used by the FSCTL_DFS_GET_REFERRALS IOCTL.
//
// Specs: [MS-DFSC] Distributed File System (DFS): Referral Protocol,
// section 2.2.2 (REQ_GET_DFS_REFERRAL) and sections 2.2.4-2.2.5
// (RESP_GET_DFS_REFERRAL and the version 1-4 referral entries). All
// integers are little-endian.
//
// The package is pure-Go and performs no I/O — dfs.go wires it onto the
// SMB2 IOCTL transport. ReferralRequest implements the smb2.Encoder
// interface (Size/Encode) so it can be used directly as the Input of an
// smb2.IoctlRequest without an adapter.
package dfsc

import (
	"encoding/binary"
	"unicode/utf16"
)

var le = binary.LittleEndian

const (
	// MaxReferralLevelV4 is the highest referral version this codec
	// requests. On STATUS_INVALID_PARAMETER the caller retries at level 3
	// then 2 (see dfs.go); the codec parses all of versions 1-4.
	MaxReferralLevelV4 = 4
	MaxReferralLevelV3 = 3
	MaxReferralLevelV2 = 2
)

// ReferralRequest is REQ_GET_DFS_REFERRAL ([MS-DFSC] 2.2.2):
//
//	MaxReferralLevel (2 bytes)
//	RequestFileName  (variable, null-terminated UTF-16LE)
type ReferralRequest struct {
	// MaxReferralLevel is the highest DFS referral version the client
	// understands. Servers may reply with a lower version.
	MaxReferralLevel uint16
	// RequestFileName is the full UNC being resolved, e.g.
	// `\nsroot\dfs\link\sub\file.csv`. It is sent as a null-terminated
	// UTF-16LE string.
	RequestFileName string
}

func (r *ReferralRequest) encodedName() []uint16 {
	return utf16.Encode([]rune(r.RequestFileName))
}

// Size returns the encoded length in bytes. It implements smb2.Encoder.
func (r *ReferralRequest) Size() int {
	// MaxReferralLevel(2) + RequestFileName(UTF-16LE) + null terminator(2)
	return 2 + len(r.encodedName())*2 + 2
}

// Encode writes the request into b, which must be at least Size() bytes.
// It implements smb2.Encoder.
func (r *ReferralRequest) Encode(b []byte) {
	le.PutUint16(b[0:2], r.MaxReferralLevel)
	off := 2
	for _, u := range r.encodedName() {
		le.PutUint16(b[off:off+2], u)
		off += 2
	}
	le.PutUint16(b[off:off+2], 0) // trailing UTF-16 NUL
}
