package idgen

import (
	"strings"
	"sync"
	"testing"
)

// TestShortSuffix_HasRequestedLength pins the length contract. A suffix shorter
// than asked would silently weaken uniqueness, and a longer one would break a slug
// that has a maximum length.
func TestShortSuffix_HasRequestedLength(t *testing.T) {
	for _, n := range []int{1, 2, 5, 6, 8, 12, 16, 31, 32} {
		got := ShortSuffix(n)
		if len(got) != n {
			t.Errorf("ShortSuffix(%d) returned %d characters (%q)", n, len(got), got)
		}
		for _, r := range got {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Errorf("ShortSuffix(%d) = %q contains a non-hex character %q", n, got, r)
			}
		}
	}
}

// TestShortSuffix_ClampsOutOfRangeInputs covers the two inputs that would otherwise
// break a caller's assumption: zero (which would make every suffix identical) and an
// oversized request (whose truncation would not match the requested length).
func TestShortSuffix_ClampsOutOfRangeInputs(t *testing.T) {
	if got := ShortSuffix(0); len(got) != 1 {
		t.Errorf("ShortSuffix(0) = %q, want a 1-character suffix rather than an empty one", got)
	}
	if got := ShortSuffix(-5); len(got) != 1 {
		t.Errorf("ShortSuffix(-5) = %q, want a 1-character suffix", got)
	}
	if got := ShortSuffix(1000); len(got) != 32 {
		t.Errorf("ShortSuffix(1000) returned %d characters, want it clamped to 32", len(got))
	}
}

// TestShortSuffix_DoesNotRepeat is the regression test for the bug this package
// replaced, and the assertion is shaped by arithmetic rather than by intuition.
//
// # Why this is a distinct-count floor and not exact uniqueness
//
// A 6-character suffix carries 24 bits — 16,777,216 possible values — and drawing
// 10,000 of them is the birthday problem. The expected number of collisions is
// n²/2N ≈ 3, Poisson-distributed, so a correct implementation yields about 9,997
// distinct values and demanding zero repeats would fail roughly 95% of the time.
// Writing that assertion anyway would be the same mistake as the original bug:
// reasoning about randomness without doing the arithmetic.
//
// # What the bug actually looked like
//
// A UUIDv7's first 48 bits are a millisecond timestamp, so slicing its prefix
// returns an identical string for every call inside the same millisecond — the
// number of distinct values observed here would be one, or a handful, rather than
// ~9,997. The two outcomes are separated by a wide margin, which is why a floor of
// 9,900 catches the structural failure while tolerating the statistical one.
func TestShortSuffix_DoesNotRepeat(t *testing.T) {
	const (
		draws = 10_000
		// 24 bits of entropy: expected distinct ≈ 9,997, collisions ≈ Poisson(3).
		// The floor tolerates thirty times the expected collision count.
		distinctFloor = 9_900
	)

	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		seen[ShortSuffix(6)] = struct{}{}
	}

	if len(seen) < distinctFloor {
		t.Fatalf("only %d distinct suffixes from %d draws (floor %d): a timestamp-derived "+
			"implementation returns one value per millisecond, which is the bug this package "+
			"exists to remove", len(seen), draws, distinctFloor)
	}
}

// TestShortSuffix_ConsecutiveCallsDiffer targets the original bug directly.
//
// A UUIDv7-prefix implementation cannot pass this: its leading characters are a
// timestamp, so a hundred calls in a tight loop — orders of magnitude inside one
// millisecond — return the same value.
func TestShortSuffix_ConsecutiveCallsDiffer(t *testing.T) {
	const draws = 100

	first := ShortSuffix(6)
	for i := 1; i < draws; i++ {
		if got := ShortSuffix(6); got == first {
			t.Fatalf("call %d repeated the first suffix %q; consecutive calls must differ "+
				"regardless of how quickly they are made", i, first)
		}
	}
}

// TestShortSuffix_Concurrent proves the function is safe to call from many
// goroutines at once, which matters because every slug-producing path runs on a
// request goroutine.
//
// Twelve-character suffixes are used deliberately: 48 bits across 4,000 draws makes
// an accidental collision so unlikely (on the order of 4×10⁻⁹) that exact uniqueness
// can be asserted. This test is about concurrency safety, not entropy, so a longer
// suffix does not weaken what it proves.
func TestShortSuffix_Concurrent(t *testing.T) {
	const (
		goroutines   = 16
		perGoroutine = 250
		total        = goroutines * perGoroutine
	)

	var (
		mu   sync.Mutex
		seen = make(map[string]struct{}, total)
		wg   sync.WaitGroup
	)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			local := make([]string, 0, perGoroutine)
			for j := 0; j < perGoroutine; j++ {
				local = append(local, ShortSuffix(12))
			}

			mu.Lock()
			defer mu.Unlock()
			for _, s := range local {
				if _, dup := seen[s]; dup {
					t.Errorf("concurrent calls produced a duplicate suffix %q", s)
				}
				seen[s] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(seen) != total {
		t.Fatalf("collected %d distinct suffixes, want %d", len(seen), total)
	}
}

// TestShortSuffix_DistributesAcrossLeadingCharacters catches a skew that would not
// show up as a duplicate: an implementation whose first character barely varies
// produces identifiers that look distinct while clustering in a narrow space.
//
// It is also the assertion that would flag a version nibble or timestamp nibble
// leaking into position zero, which is the shape the original bug had. The floor is
// loose — a twentieth of the expected count — because the point is to catch a
// structural skew, not to audit the RNG. Judging randomness properly is the RNG's
// job, not this wrapper's.
func TestShortSuffix_DistributesAcrossLeadingCharacters(t *testing.T) {
	const draws = 10_000

	counts := make(map[rune]int, 16)
	for i := 0; i < draws; i++ {
		counts[rune(ShortSuffix(8)[0])]++
	}

	expected := draws / 16
	floor := expected / 20
	digits := "0123456789abcdef"
	for _, d := range digits {
		if counts[d] < floor {
			t.Errorf("leading character %q appeared %d times, want at least %d: the suffix is not uniform",
				d, counts[d], floor)
		}
	}
	if len(counts) != len(digits) {
		t.Errorf("only %d distinct leading characters appeared, want all %d", len(counts), len(digits))
	}
}
