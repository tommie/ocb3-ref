package ocb3

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRFC7253Vectors(t *testing.T) {
	// From https://www.rfc-editor.org/rfc/rfc7253.txt, Appendix A.
	k := "000102030405060708090A0B0C0D0E0F"
	tsts := []struct {
		K       string
		N       string
		A       string
		P       string
		C       string
		TagSize int
	}{
		{
			K: k,
			N: "BBAA99887766554433221100",
			A: "",
			P: "",
			C: "785407BFFFC8AD9EDCC5520AC9111EE6",
		}, {
			K: k,
			N: "BBAA99887766554433221101",
			A: "0001020304050607",
			P: "0001020304050607",
			C: "6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009",
		}, {
			K: k,
			N: "BBAA99887766554433221102",
			A: "0001020304050607",
			P: "",
			C: "81017F8203F081277152FADE694A0A00",
		}, {
			K: k,
			N: "BBAA99887766554433221103",
			A: "",
			P: "0001020304050607",
			C: "45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9",
		}, {
			K: k,
			N: "BBAA99887766554433221104",
			A: "000102030405060708090A0B0C0D0E0F",
			P: "000102030405060708090A0B0C0D0E0F",
			C: "571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358",
		}, {
			K: k,
			N: "BBAA99887766554433221105",
			A: "000102030405060708090A0B0C0D0E0F",
			P: "",
			C: "8CF761B6902EF764462AD86498CA6B97",
		}, {
			K: k,
			N: "BBAA99887766554433221106",
			A: "",
			P: "000102030405060708090A0B0C0D0E0F",
			C: "5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D",
		}, {
			K: k,
			N: "BBAA99887766554433221107",
			A: "000102030405060708090A0B0C0D0E0F1011121314151617",
			P: "000102030405060708090A0B0C0D0E0F1011121314151617",
			C: "1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F",
		}, {
			K: k,
			N: "BBAA99887766554433221108",
			A: "000102030405060708090A0B0C0D0E0F1011121314151617",
			P: "",
			C: "6DC225A071FC1B9F7C69F93B0F1E10DE",
		}, {
			K: k,
			N: "BBAA99887766554433221109",
			A: "",
			P: "000102030405060708090A0B0C0D0E0F1011121314151617",
			C: "221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF",
		}, {
			K: k,
			N: "BBAA9988776655443322110A",
			A: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			P: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			C: "BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240",
		}, {
			K: k,
			N: "BBAA9988776655443322110B",
			A: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			P: "",
			C: "FE80690BEE8A485D11F32965BC9D2A32",
		}, {
			K: k,
			N: "BBAA9988776655443322110C",
			A: "",
			P: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			C: "2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF",
		}, {
			K: k,
			N: "BBAA9988776655443322110D",
			A: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			P: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			C: "D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60",
		}, {
			K: k,
			N: "BBAA9988776655443322110E",
			A: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			P: "",
			C: "C5CD9D1850C141E358649994EE701B68",
		}, {
			K: k,
			N: "BBAA9988776655443322110F",
			A: "",
			P: "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			C: "4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479",
		}, {
			// Test 16. Different key. Different tag size.
			K:       "0F0E0D0C0B0A09080706050403020100",
			N:       "BBAA9988776655443322110D",
			A:       "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			P:       "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627",
			C:       "1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA",
			TagSize: 12,
		},
	}

	for i, tst := range tsts {
		k, err := hex.DecodeString(tst.K)
		if err != nil {
			t.Fatalf("Invalid K=%q: %v", tst.K, err)
		}
		n, err := hex.DecodeString(tst.N)
		if err != nil {
			t.Fatalf("Invalid N=%q: %v", tst.N, err)
		}
		a, err := hex.DecodeString(tst.A)
		if err != nil {
			t.Fatalf("Invalid A=%q: %v", tst.A, err)
		}
		p, err := hex.DecodeString(tst.P)
		if err != nil {
			t.Fatalf("Invalid P=%q: %v", tst.P, err)
		}
		c, err := hex.DecodeString(tst.C)
		if err != nil {
			t.Fatalf("Invalid C=%q: %v", tst.C, err)
		}

		var opts []Opt
		if tst.TagSize != 0 {
			opts = append(opts, TagSize(tst.TagSize))
		}
		cx, err := New(k, opts...)
		if err != nil {
			t.Fatalf("New(%q) failed: %v", tst.K, err)
		}
		if cx.NonceSize() != len(n) {
			t.Fatalf("NonceSize: got %d, want %d", cx.NonceSize(), len(n))
		}
		if cx.Overhead() != len(c)-len(p) {
			t.Fatalf("Overhead [test %d]: got %d, want %d", i, cx.Overhead(), len(c)-len(p))
		}

		if gotC := cx.Seal(nil, n, p, a); !bytes.Equal(gotC, c) {
			t.Fatalf("Seal(%q, %q, %q): got %q, want %q", tst.N, tst.P, tst.A, hex.EncodeToString(gotC), tst.C)
		}

		if gotP, err := cx.Open(nil, n, c, a); err != nil {
			t.Fatalf("Open(%q, %q, %q) failed: %v", tst.N, tst.C, tst.A, err)
		} else if !bytes.Equal(gotP, p) {
			t.Fatalf("Open(%q, %q, %q): got %q, want %q", tst.N, tst.C, tst.A, hex.EncodeToString(gotP), tst.P)
		}
	}
}

func TestAESInfoString(t *testing.T) {
	if want := "OCB3 "; !strings.HasPrefix(AESInfoString, want) {
		t.Errorf("AESInfoString: got %q, want prefix %q", AESInfoString, want)
	}
}
