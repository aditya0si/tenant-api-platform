package project

import (
	"strings"
	"testing"
)

// TestNormalizePageSize pins the clamping behaviour. Clamping rather than
// erroring is deliberate: a client asking for 1000 items is not doing anything
// wrong, it simply cannot have them, and answering with as much as the service
// will serve is more useful than failing the request.
func TestNormalizePageSize(t *testing.T) {
	cases := []struct {
		requested int
		want      int
	}{
		{0, DefaultPageSize},
		{-1, DefaultPageSize},
		{-1000, DefaultPageSize},
		{1, 1},
		{20, 20},
		{MaxPageSize, MaxPageSize},
		{MaxPageSize + 1, MaxPageSize},
		{100000, MaxPageSize},
	}
	for _, tc := range cases {
		if got := NormalizePageSize(tc.requested); got != tc.want {
			t.Errorf("NormalizePageSize(%d) = %d, want %d", tc.requested, got, tc.want)
		}
	}
}

// TestSlugify pins the derived-slug rules, because a derived slug that failed the
// pattern would make project creation fail for a name the user is entitled to use —
// a confusing error about a field they never filled in.
func TestSlugify(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"Payments API", "payments-api"},
		{"payments api", "payments-api"},
		{"  Payments   API  ", "payments-api"},
		{"Data-Platform", "data-platform"},
		{"Data  --  Platform", "data-platform"},
		{"v2.0 Migration", "v2-0-migration"},
		{"Ünïcödé Pröject", "n-c-d-pr-ject"}, // non-ASCII folds to dashes, which then collapse
		{"a", "a-"}, // too short: gets a suffix (asserted below)
	}
	for _, tc := range cases {
		got := Slugify(tc.name)
		if tc.name == "a" {
			// A single character cannot satisfy the two-character minimum, so it is
			// padded with a random suffix rather than rejected.
			if len(got) < 2 || !strings.HasPrefix(got, "a-") {
				t.Errorf("Slugify(%q) = %q, want a padded two-character-plus slug", tc.name, got)
			}
			continue
		}
		if got != tc.want {
			t.Errorf("Slugify(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestSlugify_AlwaysSatisfiesThePattern is the property that matters, checked over
// the awkward inputs rather than the happy ones. The database CHECK constraint and
// the Go pattern must agree, or creation fails for a valid name.
func TestSlugify_AlwaysSatisfiesThePattern(t *testing.T) {
	names := []string{
		"Payments API",
		"!!!",
		"   ",
		"-",
		"--",
		"a",
		"1",
		"Ünïcödé",
		"日本語のプロジェクト",
		strings.Repeat("x", 500),              // longer than the pattern allows
		strings.Repeat("Very Long Name ", 50), // reduces past the limit
		"ends with punctuation!",
		"emoji 🚀 project",
		"\t\t tabs \n\n newlines \r\n",
	}
	for _, name := range names {
		slug := Slugify(name)
		if !slugPattern.MatchString(slug) {
			t.Errorf("Slugify(%q) = %q, which does not satisfy %s", name, slug, slugPattern)
		}
		if len(slug) > 63 {
			t.Errorf("Slugify(%q) = %q, longer than the 63-character limit", name, slug)
		}
	}
}

// TestValidateCreate covers the boundary validation, each arm corresponding to a
// distinct client mistake.
func TestValidateCreate(t *testing.T) {
	t.Run("derives a slug when none is supplied", func(t *testing.T) {
		got, err := validateCreate(CreateInput{Name: "Payments API"})
		if err != nil {
			t.Fatalf("validateCreate: %v", err)
		}
		if got.Slug != "payments-api" {
			t.Fatalf("slug = %q, want payments-api", got.Slug)
		}
	})

	t.Run("keeps a supplied slug", func(t *testing.T) {
		got, err := validateCreate(CreateInput{Name: "Payments API", Slug: "payments"})
		if err != nil {
			t.Fatalf("validateCreate: %v", err)
		}
		if got.Slug != "payments" {
			t.Fatalf("slug = %q, want payments (a supplied slug must win)", got.Slug)
		}
	})

	t.Run("trims the name", func(t *testing.T) {
		got, err := validateCreate(CreateInput{Name: "  Payments  "})
		if err != nil {
			t.Fatalf("validateCreate: %v", err)
		}
		if got.Name != "Payments" {
			t.Fatalf("name = %q, want trimmed", got.Name)
		}
	})

	bad := []struct {
		name string
		in   CreateInput
	}{
		{"empty name", CreateInput{Name: ""}},
		{"whitespace name", CreateInput{Name: "   "}},
		{"name too long", CreateInput{Name: strings.Repeat("x", 201)}},
		{"description too long", CreateInput{Name: "ok", Description: strings.Repeat("x", 2001)}},
		{"uppercase supplied slug", CreateInput{Name: "ok", Slug: "Payments"}},
		{"supplied slug with underscore", CreateInput{Name: "ok", Slug: "pay_ments"}},
		{"supplied slug too short", CreateInput{Name: "ok", Slug: "a"}},
		{"supplied slug starting with a dash", CreateInput{Name: "ok", Slug: "-payments"}},
		{"supplied slug with a space", CreateInput{Name: "ok", Slug: "pay ments"}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := validateCreate(tc.in); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
}

// TestBindingFilter_IsCanonical guards a subtle failure: the filter rendering is
// hashed into the cursor's binding, so if two encodes of the same logical query
// disagreed, a client would be told that the cursor the server just issued is
// invalid. The assertion is that the rendering is total and stable.
func TestBindingFilter_IsCanonical(t *testing.T) {
	cases := []struct {
		filter ListFilter
		want   string
	}{
		{ListFilter{IncludeArchived: false}, "archived=false"},
		{ListFilter{IncludeArchived: true}, "archived=true"},
	}
	for _, tc := range cases {
		got := bindingFilter(tc.filter)
		if got != tc.want {
			t.Errorf("bindingFilter(%+v) = %q, want %q", tc.filter, got, tc.want)
		}
		if again := bindingFilter(tc.filter); again != got {
			t.Errorf("bindingFilter is not stable for %+v: %q then %q", tc.filter, got, again)
		}
	}

	// The two filters must be distinguishable, or a cursor minted for one listing
	// would be accepted by the other.
	if bindingFilter(ListFilter{IncludeArchived: true}) == bindingFilter(ListFilter{IncludeArchived: false}) {
		t.Fatal("the two filters render identically, so cursors cannot be bound to one of them")
	}
}
