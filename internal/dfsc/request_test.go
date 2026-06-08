package dfsc

import (
	"bytes"
	"testing"
)

func TestReferralRequest_EncodeGolden(t *testing.T) {
	// MaxReferralLevel=4, RequestFileName=`\a\b`.
	//   04 00                            MaxReferralLevel = 4
	//   5C 00 61 00 5C 00 62 00          "\a\b" UTF-16LE
	//   00 00                            trailing NUL
	want := []byte{
		0x04, 0x00,
		0x5C, 0x00, 0x61, 0x00, 0x5C, 0x00, 0x62, 0x00,
		0x00, 0x00,
	}

	req := &ReferralRequest{MaxReferralLevel: MaxReferralLevelV4, RequestFileName: `\a\b`}

	if got := req.Size(); got != len(want) {
		t.Fatalf("Size() = %d, want %d", got, len(want))
	}

	got := make([]byte, req.Size())
	req.Encode(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("Encode() =\n  % X\nwant\n  % X", got, want)
	}
}

func TestReferralRequest_SizeMatchesEncode(t *testing.T) {
	// Exercises a multi-byte UNC including a non-ASCII rune to confirm
	// Size() and Encode() stay in lock-step (a mismatch would panic the
	// IOCTL encoder on a short buffer).
	for _, name := range []string{
		`\nsroot\dfs\link\sub\file.csv`,
		`\srv\share\rapporté.csv`,
		`\a`,
	} {
		req := &ReferralRequest{MaxReferralLevel: MaxReferralLevelV4, RequestFileName: name}
		buf := make([]byte, req.Size())
		req.Encode(buf) // must not panic / overrun
		// Last two bytes must be the NUL terminator.
		if buf[len(buf)-2] != 0 || buf[len(buf)-1] != 0 {
			t.Fatalf("%q: missing UTF-16 NUL terminator: % X", name, buf[len(buf)-2:])
		}
	}
}
